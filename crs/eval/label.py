import argparse
import asyncio
import random

from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncIterator, Optional

from crs import config
from crs.app.app_meta import run_global_exit_stack
from crs.agents.vuln_analyzer import CRSVuln
from crs.common.aio import Path
from crs.common.types import AnalyzedVuln, VulnReport, Result, Ok, CRSError
from crs.common.utils import require, requireable,  LimitedTaskGroup

from crs.eval import EvalDB, task_from_id

from crs_rust import logger

DEFAULT_SAMPLES = 100

LABEL_MODELS = ["claude-sonnet-4-20250514", "o3-2025-04-16"]
class Labeler:
    def __init__(self, db: Path):
        self.evals = EvalDB(db)

    @requireable
    async def analyze_report(self, report: VulnReport, model: str) -> Result[Optional[AnalyzedVuln]]:
        model_tok = config.MODEL.set(model)
        model_map_tok = config.MODEL_MAP.set({})
        try:
            task = require(await task_from_id(report.task_uuid))
            res = require(await CRSVuln.from_task(task).analyze_vuln_report(report))
            return Ok(res.positive)
        finally:
            config.MODEL.reset(model_tok)
            config.MODEL_MAP.reset(model_map_tok)

    @requireable
    async def label_cluster_report(self, cluster_id: int, report: VulnReport) -> Result[Optional[int]]:
        model = None
        result: Optional[AnalyzedVuln] = None
        for model in LABEL_MODELS:
            result = require(await self.analyze_report(report, model))
            if result is None:
                logger.info(f"{model=} rejected {cluster_id=}, labeling false positive")
                await self.evals.label_cluster(cluster_id, False, model)
                break
            logger.info(f"{model=} accepted {cluster_id=}, continuing")
        else:
            assert model is not None
            assert result is not None
            logger.info(f"all models accepted {cluster_id=}, labeling true positive")
            await self.evals.label_cluster(cluster_id, True, model)
            vuln_id = await self.evals.add_vuln(cluster_id, report.task_uuid, result)
            logger.info(f"added {vuln_id=} for {cluster_id=}")
            return Ok(vuln_id)
        return Ok(None)

    @requireable
    async def label_cluster(self, cluster_id: int) -> Result[Optional[int]]:
        _, report = await self.evals.get_cluster_report(cluster_id)
        return await self.label_cluster_report(cluster_id, report)

    @requireable
    async def label_clusters(self, samples: int = DEFAULT_SAMPLES) -> Result[None]:
        logger.info("labeling report clusters...")
        async with LimitedTaskGroup(200) as tg:
            unlabeled = await self.evals.get_unlabeled_clustered_reports()
            random.shuffle(unlabeled)
            for cluster_id, report in unlabeled[:samples]:
                _ = tg.create_task(
                    self.label_cluster_report(cluster_id, report),
                    name=f"label_cluster({cluster_id})"
                )
                await asyncio.sleep(0)
            pass
        return Ok(None)

    @staticmethod
    @asynccontextmanager
    async def pinned(db: Path) -> AsyncIterator['Labeler']:
        labeler = Labeler(db)
        async with AsyncExitStack() as stack:
            _ = await stack.enter_async_context(labeler.evals.sqlite_pin())
            yield labeler

async def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--db",
        type=str,
        required=True,
        help="path to the output db"
    )
    _ = parser.add_argument(
        "--samples",
        type=int,
        help="number of random samples to label",
        default=DEFAULT_SAMPLES
    )
    _ = parser.add_argument(
        "--cluster-id",
        type=int,
        help="specific cluster to label"
    )
    args = parser.parse_args()
    db = Path(args.db)
    if not await db.parent.exists():
        raise CRSError(f"db path parent {db.parent} does not exist")
    async with asyncio.TaskGroup() as tg, Labeler.pinned(Path(args.db)) as labeler:
        exit_stack_task = tg.create_task(run_global_exit_stack(), name='exit_stack')
        try:
            if args.cluster_id:
                _ = (await labeler.label_cluster(args.cluster_id)).unwrap()
                return
            if args.samples:
                (await labeler.label_clusters(samples=args.samples)).unwrap()
        finally:
            _ = exit_stack_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())