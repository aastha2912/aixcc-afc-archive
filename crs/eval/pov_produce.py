import argparse
import asyncio
import random

from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncIterator
from uuid import UUID

from crs.app.app_meta import run_global_exit_stack
from crs.common.aio import Path
from crs.common.types import Result, Ok, Err, CRSError, AnalyzedVuln
from crs.common.utils import require, requireable, LimitedTaskGroup
from crs.agents.pov_producer import CRSPovProducer, ConfirmedPOVProducerResult

from crs.eval import task_from_id, EvalDB, Evaler, EvalResult

from crs_rust import logger

DEFAULT_SAMPLES = 100

class POVEvalResult(EvalResult):
    pass

class POVProduceEvaler(Evaler[POVEvalResult]):
    def __init__(self, db_path: Path):
        self.evals = EvalDB(db_path)

    @requireable
    async def produce_pov(self, task_uuid: UUID, vuln: AnalyzedVuln) -> Result[bool]:
        task = require(await task_from_id(task_uuid))
        _ = require(await task.project.init_harness_info())
        match await CRSPovProducer.from_task(task).produce_pov(vuln, 0):
            case Ok(ConfirmedPOVProducerResult()):
                return Ok(True)
            case _:
                return Ok(False)

    async def produce_pov_for_vuln(self, vuln_id: int) -> Result[bool]:
        task_uuid, vuln = await self.evals.get_vuln(vuln_id)
        return await self.produce_pov(task_uuid, vuln)

    async def run_eval(self, samples: int) -> Result[POVEvalResult]:
        tasks = list[tuple[AnalyzedVuln, asyncio.Task[Result[bool]]]]()
        async with LimitedTaskGroup(50) as tg:
            vulns = await self.evals.get_vulns()
            vulns = random.sample(vulns, min(len(vulns), samples))
            for task_uuid, vuln in vulns:
                tasks.append((
                    vuln,
                    tg.create_task(
                        self.produce_pov(task_uuid, vuln),
                        name=f"produce_pov({task_uuid}, {vuln.function})"
                    )
                ))

        successes = 0
        failures = 0
        errors = 0
        for vuln, task in tasks:
            match await task:
                case Ok(True):
                    successes += 1
                case Ok(False):
                    failures += 1
                case Ok(_):
                    raise NotImplementedError # unreachable, just making pyright happy
                case Err(e):
                    logger.warning(f"Error producing pov for {vuln.function=}: {repr(e)}")
                    errors += 1
        return Ok(POVEvalResult(
            samples=samples,
            successes=successes,
            failures=failures,
            errors=errors
        ))

    @staticmethod
    @asynccontextmanager
    async def pinned(db: Path) -> AsyncIterator['POVProduceEvaler']:
        evaler = POVProduceEvaler(db)
        async with AsyncExitStack() as stack:
            _ = await stack.enter_async_context(evaler.evals.sqlite_pin())
            yield evaler

async def main():
    parser = argparse.ArgumentParser()
    _ = parser.add_argument(
        "--db",
        type=str,
        required=True,
        help="path to the eval dataset db"
    )
    _ = parser.add_argument(
        "--samples",
        type=int,
        help="how many samples of true/false positives to score, defaults to running all",
        default=DEFAULT_SAMPLES
    )
    _ = parser.add_argument(
        "--vuln-id",
        type=int,
        help="which vuln id to test"
    )
    _ = parser.add_argument(
        "--debug",
        action="store_true",
        help="whether to debug the scoring by asking for explanation and prompt feedback"
    )
    _ = parser.add_argument(
        "--seed",
        type=str,
        help="random seed for the sampling"
    )
    args = parser.parse_args()
    db = Path(args.db)
    if not await db.parent.exists():
        raise CRSError(f"db path parent {db.parent} does not exist")

    if args.seed:
        random.seed(args.seed)

    async with asyncio.TaskGroup() as tg, POVProduceEvaler.pinned(db) as evaler:
        exit_stack_task = tg.create_task(run_global_exit_stack(), name='exit_stack')
        try:
            if args.vuln_id:
                _ = (await evaler.produce_pov_for_vuln(args.vuln_id)).unwrap()
                return
            result = (await evaler.run_eval(args.samples)).unwrap()
            logger.info("Result: {successes=} {failures=}", **result.model_dump())
        finally:
            _ = exit_stack_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())