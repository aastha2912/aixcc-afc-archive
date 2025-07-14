import aiosqlite
import asyncio
import itertools
import orjson
import sqlite3

from crs.common.aio import Path
from pydantic import BaseModel, TypeAdapter
from pydantic.json import pydantic_encoder
from typing import Optional, Any, Iterable, Sequence, Type, Union, overload, get_args
from uuid import UUID

from .models import *
from crs import config
from crs.agents.pov_producer import HarnessInputEncoderResult

from crs.common import types, utils
from crs.common.constants import MAX_POV_LENGTH
from crs.common.sqlite import SQLiteDB

DECODER_TYPE_LOOKUP: dict[str, Type[types.Decoder]] = {t.__name__: t for t in utils.all_subclasses(types.Decoder)}

# convert UUIDs to str
aiosqlite.register_adapter(UUID, str)
aiosqlite.register_converter("UUID", utils.bytes_to_uuid)

SubmissionResponse = Union[
    POVSubmissionResponse,
    PatchSubmissionResponse,
    BundleSubmissionResponseVerbose,
    FreeformResponse,
    SARIFSubmissionResponse,
    SarifAssessmentResponse
]
SUBMISSION_TYPE_LOOKUP: dict[str, Type[SubmissionResponse]] = {t.__name__: t for t in get_args(SubmissionResponse)}

MAX_PATCH_LENGTH = 102400

class Bundle(BaseModel):
    id: int
    task_uuid: UUID
    vuln_id: int
    patch_id: Optional[int]
    pov_id: Optional[int]
    sarif_id: Optional[UUID]
    submission_id: Optional[UUID]

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        function TEXT NOT NULL,
        file TEXT NOT NULL,
        description TEXT NOT NULL,
        source TEXT,
        sarif_id UUID,
        function_range TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS vulns (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        function TEXT NOT NULL,
        file TEXT NOT NULL,
        description TEXT NOT NULL,
        conditions TEXT NOT NULL,
        report_id INTEGER,
        source TEXT NOT NULL,
        sarif_id UUID,
        submission_id UUID,

        FOREIGN KEY(report_id) REFERENCES reports(id)
    );
    """,
    f"""
    CREATE TABLE IF NOT EXISTS povs (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        harness_name TEXT NOT NULL,
        sanitizer TEXT NOT NULL,
        engine TEXT NOT NULL,
        output TEXT NOT NULL,
        dedup TEXT NOT NULL,
        stack TEXT NOT NULL,
        vuln_id INTEGER,
        pov BLOB NOT NULL CHECK(length(pov) < {MAX_POV_LENGTH}),
        pov_python TEXT,
        submission_id UUID,

        FOREIGN KEY(vuln_id) REFERENCES vulns(id)
    );
    """,
    f"""
    CREATE TABLE IF NOT EXISTS patches (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        vuln_id INTEGER NOT NULL,
        diff TEXT NOT NULL CHECK(length(diff) < {MAX_PATCH_LENGTH}),
        artifacts TEXT NOT NULL,
        submission_id UUID,

        FOREIGN KEY(vuln_id) REFERENCES vulns(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS patch_results (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        patch_id INTEGER NOT NULL,
        pov_id INTEGER NOT NULL,
        patched BOOLEAN NOT NULL,

        FOREIGN KEY(patch_id) REFERENCES patches(id),
        FOREIGN KEY(pov_id) REFERENCES povs(id),
        UNIQUE(patch_id, pov_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS bundles (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        vuln_id INTEGER NOT NULL,
        patch_id INTEGER,
        pov_id INTEGER,
        sarif_id UUID,
        submission_id UUID,

        UNIQUE(vuln_id),
        UNIQUE(patch_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS submissions (
        id UUID PRIMARY KEY,
        task_id TEXT NOT NULL,
        cls TEXT NOT NULL,
        status TEXT NOT NULL,
        json BLOB NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS decoders (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        harness_num INTEGER NOT NULL,
        cls TEXT NOT NULL,
        json BLOB NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS encoders (
        id INTEGER PRIMARY KEY,
        task_uuid UUID NOT NULL,
        project_name TEXT NOT NULL,
        harness_num INTEGER NOT NULL,
        encoder_python TEXT NOT NULL,
        harness_notes TEXT NOT NULL,
        decoder_type TEXT
    );
    """,
]

class ProductsDB(SQLiteDB):
    def __init__(self, db_path: str | Path = config.DATA_DIR / "products.sqlite3"):
        super().__init__(db_path, SCHEMA, detect_types=sqlite3.PARSE_DECLTYPES)
        self._lock = asyncio.Lock()
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

    async def add_reports(
        self,
        reports: Iterable[types.VulnReport],
    ) -> list[int]:
        ids: list[int] = []
        async with self.sqlite_connect() as conn:
            next_id = await self.get_counter(conn, "reports")
            def track_id() -> int:
                _id = next(next_id)
                ids.append(_id)
                return _id

            _ = await conn.executemany(
                """
                INSERT INTO reports (
                    id, task_uuid, project_name, function, file, description, source, sarif_id, function_range
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [(track_id(), r.task_uuid, r.project_name, r.function, r.file, r.description, r.source, r.sarif_id,
                  ":".join(map(str, r.function_range)) if r.function_range else None)
                 for r in reports]
            )
            await conn.commit()
        return ids

    async def get_report(self, report_id: int) -> Optional[types.VulnReport]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, project_name, function, file, description, source, sarif_id, function_range
                FROM reports
                WHERE id = (?)
                """,
                (report_id,)
            )
            row = await cur.fetchone()
            if row is None:
                return None

            return types.VulnReport(
                task_uuid=row[0],
                project_name=row[1],
                function=row[2],
                file=row[3],
                description=row[4],
                source=row[5],
                sarif_id=row[6],
                function_range=tuple(map(int, row[7].split(":"))) if row[7] else None # type: ignore
            )

    async def add_povs(
        self,
        povs: Iterable[types.POVRunData]
    ) -> list[int]:
        ids: list[int] = []
        async with self.sqlite_connect() as conn:
            next_id = await self.get_counter(conn, "povs")
            def track_id() -> int:
                _id = next(next_id)
                ids.append(_id)
                return _id

            _ = await conn.executemany(
                """
                INSERT INTO povs (
                    id, task_uuid, project_name, harness_name, sanitizer, engine, pov, output, pov_python, dedup, stack
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (track_id(), pov.task_uuid, pov.project_name, pov.harness, pov.sanitizer, pov.engine, pov.input, pov.output, pov.python, pov.dedup, pov.stack)
                    for pov in povs
                ]
            )
            _ = await conn.commit()
        return ids

    async def get_pov(self, pov_id: int) -> Optional[types.POVRes]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, project_name, harness_name, sanitizer, engine, pov_python, pov, output, dedup, stack, vuln_id
                FROM povs
                WHERE id = (?)
                """,
                (pov_id,)
            )
            row = await cur.fetchone()
            if row is None:
                return None

            return types.POVRes(
                task_uuid=row[0],
                project_name=row[1],
                harness=row[2],
                sanitizer=row[3],
                engine=row[4],
                python=row[5],
                input=row[6],
                output=row[7],
                dedup=row[8],
                stack=row[9],
                vuln_id=row[10]
            )

    async def add_vuln(
        self,
        task: UUID,
        project: str,
        vuln: types.AnalyzedVuln,
        source: str,
        report_id: Optional[int] = None,
        sarif_id: Optional[UUID] = None
    ) -> int:
        async with self.sqlite_connect() as conn:
            rowid = next(await self.get_counter(conn, "vulns"))
            _ = await conn.execute(
                """
                INSERT INTO vulns (
                    id, task_uuid, project_name, function, file, description, conditions, source, report_id, sarif_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (rowid, task, project, vuln.function, vuln.file, vuln.description, vuln.conditions, source, report_id, sarif_id)
            )
            _ = await conn.commit()
            return rowid

    async def set_vuln_sarif(self, vuln_id: int, sarif_id: Optional[UUID]) -> None:
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                UPDATE vulns
                SET sarif_id = ?
                WHERE id = ?
                """,
                (sarif_id, vuln_id)
            )
            _ = await conn.commit()

    async def add_patch(self, patch: types.PatchRes):
        async with self.sqlite_connect() as conn:
            rowid = next(await self.get_counter(conn, "patches"))
            data = await asyncio.to_thread(orjson.dumps, patch.artifacts, default=pydantic_encoder)
            _ = await conn.execute(
                """
                INSERT INTO patches (
                    id, task_uuid, project_name, vuln_id, diff, artifacts
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rowid, patch.task_uuid, patch.project_name, patch.vuln_id, patch.diff, data)
            )
            _ = await conn.commit()
            return rowid

    async def add_patch_results(self, task: UUID, results: list[tuple[int, int, bool]]):
        async with self.sqlite_connect() as conn:
            _ = await conn.executemany(
                """
                INSERT INTO patch_results (task_uuid, patch_id, pov_id, patched) VALUES (?, ?, ?, ?)
                ON CONFLICT(patch_id, pov_id) DO UPDATE SET patched = excluded.patched
                """,
                [(task, *r) for r in results]
            )
            await conn.commit()

    async def get_patch_results(
        self,
        task: UUID,
        patch_id: Optional[int] = None,
        vuln_id: Optional[int] = None,
        pov_id: Optional[int] = None,
        patched: Optional[bool] = None
    ) -> list[tuple[int, int, bool]]:
        async with self.sqlite_connect() as conn:
            clauses: list[str] = ["patch_results.task_uuid = ?"]
            args: list[Any] = [task]
            if patch_id is not None:
                clauses.append("patch_id = ?")
                args.append(patch_id)
            if vuln_id is not None:
                clauses.append("patches.vuln_id = ?")
                args.append(vuln_id)
                clauses.append("povs.vuln_id = ?")
                args.append(vuln_id)
            if pov_id is not None:
                clauses.append("pov_id = ?")
                args.append(pov_id)
            if patched is not None:
                clauses.append("patched = ?")
                args.append(patched)

            cur = await conn.execute(
                f"""
                SELECT patch_id, pov_id, patched FROM patch_results
                JOIN patches ON patch_id=patches.id
                JOIN povs ON pov_id=povs.id
                {'WHERE' if clauses else ''}
                {' AND '.join(clauses)};
                """,
                args
            )
            return [tuple(row) async for row in cur]

    async def assign_vuln_to_pov(self, pov_id: int, vuln_id: int):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                UPDATE povs SET vuln_id = (?) WHERE id = (?)
                """,
                (vuln_id, pov_id)
            )
            await conn.commit()

    async def get_vulns_for_task(self, task: UUID) -> dict[int, types.AnalyzedVuln]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, function, file, description, conditions FROM vulns WHERE task_uuid = (?)
                """,
                (task,)
            )
            res: dict[int, types.AnalyzedVuln] = {}
            for row in await cur.fetchall():
                res[row[0]] = types.AnalyzedVuln(
                    function=row[1],
                    file=row[2],
                    description=row[3],
                    conditions=row[4]
                )
            return res

    async def get_vuln(self, id: int) -> Optional[tuple[UUID, str, types.AnalyzedVuln]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, source, function, file, description, conditions FROM vulns WHERE id = (?)
                """,
                (id,)
            )
            if row := await cur.fetchone():
                return row[0], row[1], types.AnalyzedVuln(
                    function=row[2],
                    file=row[3],
                    description=row[4],
                    conditions=row[5]
                )
            return None

    async def get_vuln_for_stacktrace(self, task: UUID, stack: str) -> Optional[int]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT vuln_id FROM povs WHERE vuln_id IS NOT NULL AND task_uuid = (?) AND stack = (?)
                """,
                (task, stack)
            )
            if row := await cur.fetchone():
                return row[0]
            return None

    async def get_povs_for_vuln(self, vuln_id: int) -> dict[int, types.POVRes]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, task_uuid, project_name, harness_name, sanitizer, engine, pov_python, pov, output, dedup, stack, vuln_id
                FROM povs
                WHERE vuln_id = (?)
                """,
                (vuln_id,)
            )
            res: dict[int, types.POVRes] = {}
            for row in await cur.fetchall():
                res[row[0]] = types.POVRes(
                    task_uuid=row[1],
                    project_name=row[2],
                    harness=row[3],
                    sanitizer=row[4],
                    engine=row[5],
                    python=row[6],
                    input=row[7],
                    output=row[8],
                    dedup=row[9],
                    stack=row[10],
                    vuln_id=row[11]
                )
            return res

    async def get_submittable_pov_ids_for_vuln(self, vuln_id: int) -> list[int]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT povs.id
                FROM povs
                LEFT JOIN submissions on submission_id = submissions.id
                WHERE povs.vuln_id = (?) AND (submissions.status IS NULL OR submissions.status IN ('accepted', 'passed'))
                """,
                (vuln_id,)
            )
            return [row[0] async for row in cur]

    async def get_povs_for_task(self, task: UUID) -> dict[int, types.POVRes]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, task_uuid, project_name, harness_name, sanitizer, engine, pov_python, pov, output, dedup, stack, vuln_id
                FROM povs
                WHERE task_uuid = (?)
                """,
                (task,)
            )
            res: dict[int, types.POVRes] = {}
            for row in await cur.fetchall():
                res[row[0]] = types.POVRes(
                    task_uuid=row[1],
                    project_name=row[2],
                    harness=row[3],
                    sanitizer=row[4],
                    engine=row[5],
                    python=row[6],
                    input=row[7],
                    output=row[8],
                    dedup=row[9],
                    stack=row[10],
                    vuln_id=row[11]
                )
            return res

    async def get_patch(self, id: int) -> Optional[types.PatchRes]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, project_name, diff, vuln_id, artifacts FROM patches WHERE id = (?)
                """,
                (id,)
            )
            row = await cur.fetchone()
            if row is None:
                return None
            return types.PatchRes(
                task_uuid=row[0],
                project_name=row[1],
                diff=row[2],
                vuln_id=row[3],
                artifacts=TypeAdapter(list[types.PatchArtifact]).validate_json(row[4])
            )

    async def get_submittable_patch_ids_for_vuln(self, vuln_id: int) -> list[int]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT patches.id
                FROM patches
                LEFT JOIN submissions on submission_id = submissions.id
                WHERE patches.vuln_id = (?) AND (submissions.status IS NULL OR submissions.status IN ('accepted', 'passed'))
                """,
                (vuln_id,)
            )
            return [row[0] async for row in cur]

    async def get_patches_for_task(self, task: UUID) -> dict[int, types.PatchRes]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, task_uuid, project_name, diff, vuln_id, artifacts FROM patches WHERE task_uuid = (?)
                """,
                (task,)
            )
            res: dict[int, types.PatchRes] = {}
            for row in await cur.fetchall():
                res[row[0]] = types.PatchRes(
                    task_uuid=row[1],
                    project_name=row[2],
                    diff=row[3],
                    vuln_id=row[4],
                    artifacts=TypeAdapter(list[types.PatchArtifact]).validate_json(row[5])
                )
            return res

    async def get_or_create_bundle(self, task: UUID, vuln_id: int) -> Bundle:
        async with self.sqlite_connect() as conn:
            _ = await conn.execute("INSERT OR IGNORE INTO bundles (task_uuid, vuln_id) VALUES (?, ?)", (task, vuln_id))
            await conn.commit()
            cur = await conn.execute(
                """
                SELECT id, task_uuid, vuln_id, patch_id, pov_id, sarif_id, submission_id
                FROM bundles
                WHERE task_uuid = ? AND vuln_id = ?
                """,
                (task, vuln_id)
            )
            row = await cur.fetchone()
            # should always exist because we just inserted it
            assert row is not None
            return Bundle(
                id=row[0],
                task_uuid=row[1],
                vuln_id=row[2],
                patch_id=row[3],
                pov_id=row[4],
                sarif_id=row[5],
                submission_id=row[6]
            )

    async def clear_pov_submission(self, pov_id: int):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                    UPDATE povs
                    SET submission_id = null
                    WHERE id = ?
                """,
                (pov_id,)
            )

    async def clear_patch_submission(self, patch_id: int):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                    UPDATE patches
                    SET submission_id = null
                    WHERE id = ?
                """,
                (patch_id,)
            )

    async def update_bundle(self, bundle: Bundle):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                    UPDATE bundles
                    SET patch_id = ?, pov_id = ?, sarif_id = ?
                    WHERE id = ?
                """,
                (bundle.patch_id, bundle.pov_id, bundle.sarif_id,
                 bundle.id)
            )
            await conn.commit()

    async def delete_bundle_submission(self, bundle_id: int):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                    UPDATE bundles
                    SET submission_id = NULL
                    WHERE id = ?
                """,
                (bundle_id,)
            )
            await conn.commit()

    async def get_bundle_submissions(self, bundle_id: int) -> tuple[
        Optional[PatchSubmissionResponse],
        Optional[POVSubmissionResponse],
        Optional[SarifAssessmentResponse],
        Optional[BundleSubmissionResponseVerbose]
    ]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                    SELECT patches.submission_id, povs.submission_id, vulns.submission_id, bundles.submission_id
                    FROM bundles
                    LEFT JOIN patches ON bundles.patch_id = patches.id
                    LEFT JOIN povs ON bundles.pov_id = povs.id
                    LEFT JOIN vulns ON bundles.vuln_id = vulns.id
                    WHERE bundles.id = ?
                """,
                (bundle_id, )
            )
            assert (row := await cur.fetchone()) is not None
        return await asyncio.gather(
            self._get_submission(row[0], PatchSubmissionResponse),
            self._get_submission(row[1], POVSubmissionResponse),
            self._get_submission(row[2], SarifAssessmentResponse),
            self._get_submission(row[3], BundleSubmissionResponseVerbose)
        )

    async def put_submission(
        self,
        task_id: UUID,
        response: SubmissionResponse,
        product_table: Optional[Literal['patches', 'povs', 'vulns', 'bundles']],
        product_id: Optional[int]
    ):
        async with self.sqlite_connect() as conn:
            _ = await conn.execute(
                """
                INSERT INTO submissions (id, task_id, cls, status, json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    task_id = excluded.task_id,
                    cls = excluded.cls,
                    status = excluded.status,
                    json = excluded.json
                """,
                (response.id(), task_id, response.__class__.__name__, response.status, response.model_dump_json())
            )

            if product_table and product_id:
                _ = await conn.execute(
                    f"""
                    UPDATE {product_table} SET submission_id = ? WHERE id = ?
                    """,
                    (response.id(), product_id)
                )

            await conn.commit()

    async def _get_submission[T: SubmissionResponse](self, id: Optional[UUID], cls: type[T]) -> Optional[T]:
        if id is None:
            return None
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT json FROM submissions WHERE id = ?
                """,
                (id, )
            )
            row = await cur.fetchone()
            if row is None:
                return None
            return cls(**await asyncio.to_thread(orjson.loads, row[0]))

    async def add_decoder(
        self,
        task_uuid: UUID,
        project_name: str,
        harness_num: int,
        decoder: types.Decoder
    ) -> int:
        async with self.sqlite_connect() as conn:
            rowid = next(await self.get_counter(conn, "decoders"))
            _ = await conn.execute(
                """
                INSERT INTO decoders (
                    id, task_uuid, project_name, harness_num, cls, json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (rowid, task_uuid, project_name, harness_num, decoder.__class__.__name__, decoder.model_dump_json())
            )
            _ = await conn.commit()
            return rowid

    @overload
    async def get_decoders[T: types.Decoder](
        self,
        *,
        harness_num: int,
        cls: Type[T],
        task_uuid: UUID,
        project_name: Optional[str] = None,
    ) -> list[T]:
        ...

    @overload
    async def get_decoders[T: types.Decoder](
        self,
        *,
        harness_num: int,
        cls: Type[T],
        task_uuid: None = None,
        project_name: str,
    ) -> list[T]:
        ...

    @overload
    async def get_decoders(
        self,
        *,
        harness_num: int,
        cls: None = None,
        task_uuid: None = None,
        project_name: Optional[str] = None,
    ) -> list[types.Decoder]:
        ...

    @overload
    async def get_decoders(
        self,
        *,
        harness_num: int,
        cls: None = None,
        task_uuid: Optional[UUID] = None,
        project_name: str,
    ) -> list[types.Decoder]:
        ...

    async def get_decoders[T: types.Decoder](
        self,
        *,
        cls: Optional[Type[T]] = None,
        task_uuid: Optional[UUID] = None,
        project_name: Optional[str] = None,
        harness_num: Optional[int] = None
    ) -> Sequence[types.Decoder]:
        async with self.sqlite_connect() as conn:
            clauses: list[str] = ["harness_num = ?"]
            args: list[Any] = [harness_num]
            if task_uuid:
                clauses.append("task_uuid = ?")
                args.append(task_uuid)
            if project_name:
                clauses.append("project_name = ?")
                args.append(project_name)
            if cls is not None:
                clauses.append("cls = ?")
                args.append(cls.__name__)
            query = f"""
                SELECT cls, json
                FROM decoders
                {'WHERE' if clauses else ''}
                {' AND '.join(clauses)};
            """
            cur = await conn.execute(query, args)
            return [
                DECODER_TYPE_LOOKUP[row[0]](
                    **orjson.loads(row[1])
                )
                async for row in cur
            ]

    async def add_encoder(
        self,
        task_uuid: UUID,
        project_name: str,
        harness_num: int,
        encoder: HarnessInputEncoderResult,
        decoder_type: Optional[type[types.Decoder]]
    ):
        async with self.sqlite_connect() as conn:
            rowid = next(await self.get_counter(conn, "encoders"))
            _ = await conn.execute(
                """
                INSERT INTO encoders (
                    id, task_uuid, project_name, harness_num, encoder_python, harness_notes, decoder_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (rowid, task_uuid, project_name, harness_num, encoder.encoder_python, encoder.harness_notes,
                 decoder_type.__name__ if decoder_type else None)
            )
            _ = await conn.commit()
            return rowid

    @overload
    async def get_encoders(
        self,
        *,
        harness_num: int,
        task_uuid: UUID,
        project_name: Optional[str] = None,
        decoder_type: Optional[type[types.Decoder]] = None
    ) -> list[HarnessInputEncoderResult]:
        ...

    @overload
    async def get_encoders(
        self,
        *,
        harness_num: int,
        task_uuid: None = None,
        project_name: str,
        decoder_type: Optional[type[types.Decoder]] = None
    ) -> list[HarnessInputEncoderResult]:
        ...

    async def get_encoders(
        self,
        *,
        harness_num: int,
        task_uuid: Optional[UUID] = None,
        project_name: Optional[str] = None,
        decoder_type: Optional[type[types.Decoder]] = None
    ) -> list[HarnessInputEncoderResult]:
        async with self.sqlite_connect() as conn:
            clauses = ['harness_num = ?']
            args: list[Any] = [harness_num]
            if task_uuid:
                clauses.append("task_uuid = ?")
                args.append(task_uuid)
            if project_name:
                clauses.append("project_name = ?")
                args.append(project_name)
            if decoder_type is None:
                clauses.append("decoder_type is null")
            else:
                clauses.append("decoder_type = ?")
                args.append(decoder_type.__name__)
            query = f"""
                SELECT encoder_python, harness_notes
                FROM encoders
                WHERE
                {' AND '.join(clauses)};
                """
            cur = await conn.execute(query, args)
            return [
                HarnessInputEncoderResult(
                    encoder_python=row[0],
                    harness_notes=row[1]
                )
                async for row in cur
            ]
