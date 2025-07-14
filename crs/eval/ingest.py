import argparse
import asyncio
import orjson
import re

from contextlib import asynccontextmanager, AsyncExitStack
from collections import defaultdict
from typing import AsyncIterator, Optional, Any
from uuid import UUID

from crs.agents.triage import dedupe_vulns
from crs.app.products_db import ProductsDB
from crs.app.app import CRSWorkDB, WorkType, ReportData
from crs.common.aio import Path, open as aio_open
from crs.common.types import VulnReport, AnalyzedVuln, Result, Err, Ok, CRSError
from crs.common.utils import require, requireable, LimitedTaskGroup

from crs.eval import EvalDB, report_to_vuln, task_from_id, get_known_vulns

from crs_rust import logger

class ProductsExtractor(ProductsDB):
    def __init__(self, backup: Path):
        super().__init__(backup / "data" / "products.sqlite3")

    async def extract_reports(self) -> list[tuple[int, VulnReport]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, task_uuid, project_name, function, file, description, source, sarif_id, function_range
                FROM reports
                """
            )
            return [
                (*row[0], VulnReport(
                    task_uuid=row[1],
                    project_name=row[2],
                    function=row[3],
                    file=row[4],
                    description=row[5],
                    source=row[6],
                    sarif_id=row[7],
                    function_range=tuple(map(int, row[8].split(":"))) if row[8] else None # type: ignore
                ))
                async for row in cur
            ]

    async def extract_vulns(self) -> list[tuple[UUID, AnalyzedVuln]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT task_uuid, function, file, description, conditions
                FROM vulns
                """
            )
            return [
                (row[0], AnalyzedVuln(
                    function=row[1],
                    file=row[2],
                    description=row[3],
                    conditions=row[4]
                ))
                async for row in cur
            ]

class WorkExtractor(CRSWorkDB):
    def __init__(self, backup: Path):
        super().__init__(WorkType, backup / "data" / "work.sqlite3")

    async def extract_jobs[T](self, worktype: WorkType, cls: type[T]) -> list[tuple[int, UUID, T]]:
        async with self.sqlite_connect() as conn:
            cur = await conn.execute(
                """
                SELECT id, task_id, task_desc
                FROM jobs
                WHERE worktype = ?
                """,
                (worktype,)
            )
            return [
                (row[0], row[1], cls(**orjson.loads(row[2])))
                async for row in cur
            ]

class Ingester:
    def __init__(self, backup: Path, db: Path):
        self.backup = backup
        self.products = ProductsExtractor(backup)
        self.work = WorkExtractor(backup)
        self.evals = EvalDB(db)
        self.cluster_locks = defaultdict[tuple[str, str], asyncio.Lock](asyncio.Lock)

    @requireable
    async def ingest_known_vulns(self):
        async for backup, report_id, task, vuln in get_known_vulns():
            report = VulnReport(
                task_uuid=task.task_id,
                project_name=task.project.name,
                function=vuln.function,
                file=vuln.file,
                description=vuln.description,
                source="known"
            )
            match await self.ingest_report(report_id, report, backup=backup):
                case Ok((cluster_id, _)):
                    await self.evals.label_cluster(cluster_id, True, 'NA')
                    if (await self.evals.get_cluster_vuln(cluster_id)) is None:
                        vuln_id = await self.evals.add_vuln(cluster_id, task.task_id, vuln)
                        logger.info(f"Added {vuln_id=} for {cluster_id=}")
                case Err(e):
                    logger.warning(f"Error ingesting know vuln: {repr(e)}")
        return Ok(None)

    @requireable
    async def dedupe_reports(self, report: VulnReport, candidates: list[VulnReport]) -> Result[int]:
        if len(candidates) == 0:
            return Ok(-1)
        vulns = [report_to_vuln(r) for r in candidates]
        choice, confidence = require(await dedupe_vulns(report.project_name, report_to_vuln(report), vulns))
        logger.info(f"dedupe {choice=} {confidence=}")
        return Ok(choice)

    @asynccontextmanager
    async def log_iter(self, substr: Optional[bytes] = None) -> AsyncIterator[AsyncIterator[dict[str, Any]]]:
        async def iter_logs(log_file_iter: AsyncIterator[Path]) -> AsyncIterator[dict[str, Any]]: # noqa: ASYNC900
            async for log_file in log_file_iter:
                async with aio_open(log_file.as_posix(), "rb") as f:
                    logs = [l for l in f if (not substr or substr in l)]
                for l in logs:
                    yield orjson.loads(l.strip())
        async with self.backup.glob("logs/crs_*") as log_file_iter:
            yield iter_logs(log_file_iter)

    report_score_pattern = re.compile(r".*Report (\d+) score: ([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)")
    async def extract_report_scores(self) -> dict[int, float]:
        logger.info("extracting score_vuln score logs...")
        report_scores: dict[int, float] = {}
        async with self.log_iter(b'score: ') as it:
            async for log in it:
                if match := self.report_score_pattern.match(log["text"]):
                    raw_id, raw_score = match.groups()
                    report_scores[int(raw_id)] = float(raw_score)
        return report_scores

    async def extract_score_vuln_jobs(self) -> dict[int, tuple[UUID, ReportData]]:
        logger.info("extracting score_vuln jobs from workdb...")
        return {
            id: (task_id, data)
            for id, task_id, data in await self.work.extract_jobs(WorkType.SCORE_VULN, ReportData)
        }

    @requireable
    async def ingest_report(self, report_id: int, report: VulnReport, backup: Optional[str] = None) -> Result[tuple[int, int]]:
        backup = backup or self.backup.name
        ids = await self.evals.find_report(backup, report_id)
        if ids is not None:
            logger.info(f"skipping previously processed report {backup=} {report_id=}")
            return Ok(ids)

        async with self.cluster_locks[report.function, report.file]:
            candidates = await self.evals.get_clustered_reports_for_func(report.function, report.file)
            idx = require(await self.dedupe_reports(report, [r for _, r in candidates]))
            cluster_id = -1 if idx < 0 else candidates[idx][0]
            logger.info(f"inserting {report_id=} with {cluster_id=}")
            return Ok(await self.evals.add_report(backup, report_id, report, cluster_id))

    @requireable
    async def ingest_reports(self) -> Result[None]:
        logger.info("extracting reports from productsdb...")
        reports = {report_id: report for report_id, report in await self.products.extract_reports()}
        async with LimitedTaskGroup(500) as tg:
            for report_id, report in reports.items():
                _ = tg.create_task(self.ingest_report(report_id, report), name=f'label_report({report_id=})')
                await asyncio.sleep(0)
        return Ok(None)

    @requireable
    async def extract_vulns(self, backup: Path, db: Path) -> Result[None]:
        logger.info("extracting vulns from productsdb...")
        clusters: defaultdict[tuple[UUID, str, str], list[AnalyzedVuln]] = defaultdict(list)
        products = ProductsExtractor(backup)
        for task_uuid, vuln in await products.extract_vulns():
            clusters[task_uuid, vuln.function, vuln.file].append(vuln)
        #k, v = max(clusters.items(), key=lambda v: len(v[1]))
        # TODO
        return Ok(None)

    @requireable
    async def dump_errors(self) -> Result[None]:
        report_scores = await self.extract_report_scores()
        for report_id, report in await self.products.extract_reports():
            if report_id in report_scores:
                continue
            task = require(await task_from_id(report.task_uuid))
            match await task.project.searcher.read_definition(report.function, report.file):
                case Ok(_):
                    logger.info(f"no error when reading definition? {report_id=} {report.file=} {report.function=}")
                    exit()
                case Err(e):
                    logger.info(f"{report_id}= was not scored: {report.file=}, {report.function=}, {report.source=}, {repr(e)=}")
                    text = require(await task.project.searcher.read_full_source(report.file))
                    in_file = report.function in text
                    if not in_file:
                        logger.error(f"{report_id}= {report.file=}, {report.function=} not in source")
                        exit()
        return Ok(None)

    @staticmethod
    @asynccontextmanager
    async def pinned(backup: Path, db: Path) -> AsyncIterator['Ingester']:
        labeler = Ingester(backup, db)
        async with AsyncExitStack() as stack:
            _ = await stack.enter_async_context(labeler.products.sqlite_pin())
            _ = await stack.enter_async_context(labeler.work.sqlite_pin())
            _ = await stack.enter_async_context(labeler.evals.sqlite_pin())
            yield labeler

async def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--backup",
        type=str,
        required=True,
        help="path to the backup"
    )
    _ = parser.add_argument(
        "--db",
        type=str,
        required=True,
        help="path to the eval dataset db"
    )
    _ = parser.add_argument(
        "--known",
        action="store_true",
        help="whether to ingest reports/vulns from known vulns"
    )
    _ = parser.add_argument(
        "--reports",
        action="store_true",
        help="whether to ingest reports from backup"
    )
    _ = parser.add_argument(
        "--errors",
        action="store_true",
        help="whether to dump error data from the backup"
    )
    args = parser.parse_args()
    backup, db = Path(args.backup), Path(args.db)
    if not await backup.exists():
        raise CRSError(f"backup path {backup} does not exist")
    if not await db.parent.exists():
        raise CRSError(f"db path parent {db.parent} does not exist")
    async with Ingester.pinned(Path(args.backup), Path(args.db)) as labeler:
        if args.known:
            (await labeler.ingest_known_vulns()).unwrap()
        if args.reports:
            (await labeler.ingest_reports()).unwrap()
        if args.errors:
            (await labeler.dump_errors()).unwrap()

if __name__ == "__main__":
    asyncio.run(main())