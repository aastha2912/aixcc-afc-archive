import aiosqlite
import itertools
import orjson
import sqlite3

from abc import ABC, abstractmethod
from pydantic import BaseModel, TypeAdapter
from typing import Optional, AsyncIterator
from uuid import UUID

from crs import config
from crs.app.api_task import api_to_crs_task
from crs.common.aio import Path
from crs.common.alru import async_once, alru_cache
from crs.common.sqlite import SQLiteDB
from crs.common.types import Result, Err, CRSError, VulnReport, AnalyzedVuln
from crs.common.utils import only_ok
from crs.modules.project import Task
from crs.modules.testing import TestProject
from crs.task_server.models import TaskDetail, Task as TaskMessage

# convert UUIDs to str
aiosqlite.register_adapter(UUID, str)
aiosqlite.register_converter("UUID", lambda b: UUID(b.decode()))

TEST_PROJECT_DIR = config.CRSROOT / ".." / "projects"
TASKS_DIR = config.CRSROOT / ".." / "tests" / "app"
API_TASKS: dict[UUID, TaskDetail] = {}
TEST_TASKS: dict[UUID, Task] = {}

KNOWN_VULNS_PATH = config.CRSROOT / ".." / "configs" / "new_vuln_commits_250523.json"

async def get_known_vulns() -> AsyncIterator[tuple[str, int, Task, AnalyzedVuln]]: # noqa: ASYNC900
    vulns = TypeAdapter(dict[str, dict[int, AnalyzedVuln]]).validate_python(
        orjson.loads(await KNOWN_VULNS_PATH.read_bytes())
    )
    for project_name, commits in vulns.items():
        project = await TestProject.from_dir(TEST_PROJECT_DIR / project_name)
        tasks = (await project.tasks()).unwrap()
        for commit, vuln in commits.items():
            yield f"{project_name}-vulns", commit, tasks[commit], vuln

def standardize_project(project_name: str):
    if project_name.startswith('example-'):
        project_name = project_name[8:]
    if project_name.startswith('afc-'):
        project_name = project_name[4:]
    if project_name.endswith("-asc"):
        project_name = project_name[:-4]
    if project_name.endswith("-theori"):
        project_name = project_name[:-7]
    return project_name

@async_once
async def _init_tasks():
    async with TASKS_DIR.walk() as walk_it:
        async for root, _, files in walk_it:
            for f in files:
                path = root / f
                if not await path.is_file() and path.suffix == ".json":
                    pass
                try:
                    msg = TaskMessage(**orjson.loads(await path.read_bytes()))
                    for task in msg.tasks:
                        API_TASKS[task.task_id] = task
                except Exception:
                    pass

@alru_cache(filter=only_ok)
async def task_from_id(task_id: UUID) -> Result[Task]:
    await _init_tasks()
    dbtask = API_TASKS.get(task_id, None)
    if dbtask is None:
        return Err(CRSError(f"missing task data for task with {task_id=}"))
    return await api_to_crs_task(dbtask)


class EvalDB(SQLiteDB):
    SCHEMA = [
        """
        CREATE TABLE IF NOT EXISTS clusters (
            id INTEGER PRIMARY KEY,
            last_model TEXT,
            label BOOLEAN
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY,
            task_uuid UUID NOT NULL,
            project_name TEXT NOT NULL,
            function TEXT NOT NULL,
            file TEXT NOT NULL,
            description TEXT NOT NULL,
            source TEXT,
            function_range TEXT,
            cluster_id INTEGER NOT NULL,
            backup TEXT NOT NULL,
            product_id INTEGER NOT NULL,

            UNIQUE(backup, product_id),
            FOREIGN KEY(cluster_id) REFERENCES clusters(id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS vulns (
            id INTEGER PRIMARY KEY,
            task_uuid UUID NOT NULL,
            function TEXT NOT NULL,
            file TEXT NOT NULL,
            description TEXT NOT NULL,
            conditions TEXT NOT NULL,

            cluster_id INTEGER NOT NULL UNIQUE,
            FOREIGN KEY(cluster_id) REFERENCES clusters(id)
        );
        """
    ]

    def __init__(self, db_path: Path):
        super().__init__(db_path=db_path, schema=self.SCHEMA, detect_types=sqlite3.PARSE_DECLTYPES)
        self.next_ids: dict[str, itertools.count[int]] = {}

    async def get_counter(self, conn: aiosqlite.Connection, table: str) -> "itertools.count[int]":
        if (next_id := self.next_ids.get(table)) is None:
            async with await conn.execute(f"SELECT max(id) FROM {table}") as cursor:
                row = await cursor.fetchone()
                maxid = 0 if not row else row[0]
            if (next_id := self.next_ids.get(table)) is not None:
                return next_id
            next_id = itertools.count((maxid or 0) + 1)
            self.next_ids[table] = next_id
        return next_id

    async def add_report(
        self,
        backup: str,
        product_id: int,
        report: VulnReport,
        cluster_id: int
    ) -> tuple[int, int]:
        async with self.sqlite_connect() as conn:
            if cluster_id < 0:
                cluster_id = next(await self.get_counter(conn, 'clusters'))
                _ = await conn.execute(
                    """
                    INSERT INTO clusters(id, last_model, label) VALUES (?, NULL, NULL)
                    """,
                    (cluster_id,)
                )
            report_id = next(await self.get_counter(conn, 'reports'))
            query = f"""
                INSERT INTO reports(
                    id, task_uuid, project_name, function, file, description, source, function_range, cluster_id, backup, product_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            _ = await conn.execute(
                query,
                (report_id, report.task_uuid, report.project_name, report.function, report.file,
                 report.description, report.source, ":".join(map(str, report.function_range)) if report.function_range else None,
                 cluster_id, backup, product_id)
            )
            _ = await conn.commit()
            return cluster_id, report_id

    async def find_report(self, backup: str, product_id: int) -> Optional[tuple[int, int]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT cluster_id, id
                FROM reports
                WHERE backup = ? AND product_id = ?
                LIMIT 1
                """,
                (backup, product_id)
            )
            row = await cur.fetchone()
            if row is None:
                return None
            return row[0], row[1]

    async def get_unlabeled_clustered_reports(self) -> list[tuple[int, VulnReport]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT cluster_id, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                WHERE rowid IN (
                    SELECT MIN(reports.rowid)
                    FROM reports
                    JOIN clusters on cluster_id = clusters.id
                    WHERE clusters.label IS NULL
                    GROUP BY cluster_id
                )
                """
            )
            return [
                (row[0], VulnReport(
                    task_uuid=row[1],
                    project_name=row[2],
                    function=row[3],
                    file=row[4],
                    description=row[5],
                    source=row[6],
                    function_range=tuple(map(int, row[7].split(":"))) if row[7] else None # type: ignore
                ))
                async for row in cur
            ]

    async def get_clustered_reports_for_func(self, function: str, file: str) -> list[tuple[int, VulnReport]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT cluster_id, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                WHERE rowid IN (
                    SELECT MIN(rowid)
                    FROM reports
                    WHERE function = ? AND file = ?
                    GROUP BY cluster_id
                )
                """,
                (function, file)
            )
            return [
                (row[0], VulnReport(
                    task_uuid=row[1],
                    project_name=row[2],
                    function=row[3],
                    file=row[4],
                    description=row[5],
                    source=row[6],
                    function_range=tuple(map(int, row[7].split(":"))) if row[7] else None # type: ignore
                ))
                async for row in cur
            ]

    async def label_cluster(self, cluster_id: int, label: bool, last_model: str):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                UPDATE clusters
                SET label = ?, last_model = ?
                WHERE id = ?
                """,
                (label, last_model, cluster_id)
            )
            await conn.commit()

    async def get_report(self, report_id: int) -> tuple[int, Optional[bool], VulnReport]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT cluster_id, clusters.label, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                JOIN clusters on reports.cluster_id=clusters.id
                WHERE reports.id = ?
                LIMIT 1
                """,
                (report_id,)
            )
            row = await cur.fetchone()
            assert row is not None
            return row[0], row[1], VulnReport(
                task_uuid=row[2],
                project_name=row[3],
                function=row[4],
                file=row[5],
                description=row[6],
                source=row[7],
                function_range=tuple(map(int, row[8].split(":"))) if row[8] else None # type: ignore
            )


    async def get_cluster_report(self, cluster_id: int) -> tuple[Optional[bool], VulnReport]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT clusters.label, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                JOIN clusters on reports.cluster_id=clusters.id
                WHERE cluster_id = ?
                LIMIT 1
                """,
                (cluster_id,)
            )
            row = await cur.fetchone()
            assert row is not None
            return row[0], VulnReport(
                task_uuid=row[1],
                project_name=row[2],
                function=row[3],
                file=row[4],
                description=row[5],
                source=row[6],
                function_range=tuple(map(int, row[7].split(":"))) if row[7] else None # type: ignore
            )

    async def get_cluster_vuln(self, cluster_id: int) -> Optional[tuple[UUID, AnalyzedVuln]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, function, file, description, conditions
                FROM vulns
                JOIN clusters on vulns.cluster_id=clusters.id
                WHERE cluster_id = ?
                LIMIT 1
                """,
                (cluster_id,)
            )
            row = await cur.fetchone()
            if row is None:
                return None
            return row[0], AnalyzedVuln(
                function=row[1],
                file=row[2],
                description=row[3],
                conditions=row[4]
            )

    async def get_labeled_reports(self, label: bool) -> list[tuple[int, bool, VulnReport]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT reports.id, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                JOIN clusters ON reports.cluster_id = clusters.id
                WHERE label = ?
                """,
                (label,)
            )
            return [
                (row[0], label, VulnReport(
                    task_uuid=row[1],
                    project_name=row[2],
                    function=row[3],
                    file=row[4],
                    description=row[5],
                    source=row[6],
                    function_range=tuple(map(int, row[7].split(":"))) if row[7] else None # type: ignore
                ))
                async for row in cur
            ]

    async def get_labeled_reports_for_task(self, task_uuid: UUID) -> list[tuple[int, bool, VulnReport]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT reports.id, label, task_uuid, project_name, function, file, description, source, function_range
                FROM reports
                JOIN clusters ON reports.cluster_id = clusters.id
                WHERE label IS NOT NULL AND task_uuid = ?
                """,
                (task_uuid,)
            )
            return [
                (row[0], row[1], VulnReport(
                    task_uuid=row[2],
                    project_name=row[3],
                    function=row[4],
                    file=row[5],
                    description=row[6],
                    source=row[7],
                    function_range=tuple(map(int, row[8].split(":"))) if row[8] else None # type: ignore
                ))
                async for row in cur
            ]

    async def add_vuln(
        self,
        cluster_id: int,
        task_uuid: UUID,
        vuln: AnalyzedVuln
    ) -> int:
        async with self.sqlite_connect() as conn:
            vuln_id = next(await self.get_counter(conn, 'vulns'))
            query = f"""
                INSERT INTO vulns (
                    id, task_uuid, function, file, description, conditions, cluster_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            _ = await conn.execute(
                query,
                (vuln_id, task_uuid, vuln.function, vuln.file, vuln.description, vuln.conditions, cluster_id)
            )
            _ = await conn.commit()
            return vuln_id

    async def get_vulns(self) -> list[tuple[UUID, AnalyzedVuln]]:
        async with self.sqlite_connect() as conn:
            query = f"""
                SELECT task_uuid, function, file, description, conditions
                FROM vulns
            """
            cur = await conn.execute(query)
            return [
                (row[0], AnalyzedVuln(
                    function=row[1],
                    file=row[2],
                    description=row[3],
                    conditions=row[4]
                ))
                async for row in cur
            ]

    async def get_vuln(self, vuln_id: int) -> tuple[UUID, AnalyzedVuln]:
        async with self.sqlite_connect() as conn:
            query = f"""
                SELECT task_uuid, function, file, description, conditions
                FROM vulns
                WHERE id = ?
            """
            cur = await conn.execute(query, (vuln_id,))
            row = await cur.fetchone()
            assert row is not None
            return row[0], AnalyzedVuln(
                function=row[1],
                file=row[2],
                description=row[3],
                conditions=row[4]
            )

def report_to_vuln(report: VulnReport) -> AnalyzedVuln:
    return AnalyzedVuln(
        function=report.function,
        file=report.file,
        description=report.description,
        conditions=""
    )


class EvalResult(BaseModel):
    samples: int
    successes: int
    failures: int
    errors: int

class Evaler[T: EvalResult](ABC):
    @abstractmethod
    async def run_eval(self, samples: int) -> Result[T]:
        ...