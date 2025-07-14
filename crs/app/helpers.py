import asyncio
import uuid
from collections import defaultdict
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Optional, Awaitable, Callable
from pydantic.dataclasses import dataclass
from pydantic import field_validator

from crs.app.counter_db import CounterView
from crs.common.aio import Path, batch_unlink
from crs.common.docker import DockerGroup, DockerScope, DockerRun, manager
from crs.common.llm_api import LLMSpendTracker
from crs.common.types import CRSError, Result, Ok, Err, POVRunData, PatchRes
from crs.common.utils import require, requireable, LimitedTaskGroup, bytes_to_uuid
from crs.common.shield import shield_and_wait, finalize
from crs.common.workdb import BulkTaskWorker
from crs.modules import project
from crs.modules.coverage import CoverageAnalyzer, Frontier
from crs.modules.fuzzing import FuzzManager

from crs_rust import logger

BULK_TRIAGE_TIMEOUT=25*60

@dataclass(slots=True)
class TaskData:
    task_id: uuid.UUID

    @field_validator('task_id', mode='before')
    @classmethod
    def _dedup_uuid(cls, v: str | uuid.UUID):
        if isinstance(v, str):
            return bytes_to_uuid(v.encode())
        return v

@dataclass(slots=True)
class CalculateCoverageData(TaskData):
    harness_num: int
    filename: str

@dataclass(slots=True)
class ProcessFuzzCrashData(TaskData):
    harness_num: int
    filename: str


type FrontierHandler = Callable[[list[Frontier]], Awaitable[None]]
class BulkCoverageWorker(BulkTaskWorker[CalculateCoverageData]):
    # how long (in seconds) to wait for more work after 1 job appears
    delay = 100
    def __init__(self, fuzzer: FuzzManager, cov: CoverageAnalyzer, frontier_handler: FrontierHandler | None = None, batchsize: Optional[int] = None):
        self.fuzzer = fuzzer
        self.cov = cov
        self.frontier_handler = frontier_handler
        super().__init__(batchsize=batchsize)

    async def _handle_work(self, work: list[CalculateCoverageData]) -> list[Result[None]]:
        harnesses = (await self.fuzzer.task.project.init_harness_info()).unwrap()
        _ = await self.cov.artifacts()
        (await self.cov.init()).unwrap()

        async with manager.scope() as scope:
            # fetch the seeds based on harness number and file name
            cms = await asyncio.gather(*(self.fuzzer.get_corpus_manager(h) for h in harnesses))

            to_run: dict[tuple[int, str], bytes] = {}
            errs: dict[tuple[int, str], Result[None]] = {}
            # TODO: gather?
            for req in work:
                try:
                    contents = await (cms[req.harness_num].seed_path / req.filename).read_bytes()
                    to_run[(req.harness_num, req.filename)] = contents
                except OSError:
                    errs[(req.harness_num, req.filename)] = Ok(None) # it's fine if a file is missing, don't re-run it

            res: list[Result[None]] = []
            match await self.cov.update_coverages(to_run, cores=scope.host.cores, scope=scope):
                case Ok(cov_res):
                    for req in work:
                        match cov_res.get((req.harness_num, req.filename)):
                            case None:
                                res.append(errs.get((req.harness_num, req.filename), Err(CRSError("unknown error"))))
                            case Ok(_):
                                res.append(Ok(None))
                            case Err() as e:
                                res.append(e)
                case _:
                    for req in work:
                        res.append(
                            errs.get((req.harness_num, req.filename), Err(CRSError("bulk coverage compute failed")))
                        )

            frontiers = await self.cov.query_frontier()
            frontiers = await self.cov.db.dedup_frontiers(frontiers, update_db=True)
            if frontiers and self.frontier_handler:
                await self.frontier_handler(frontiers)
            return res

type POVData = tuple[project.Harness, bytes]

class BulkCrashWorker(BulkTaskWorker[ProcessFuzzCrashData]):
    # how long (in seconds) to wait for more work after 1 job appears
    delay = 15

    def __init__(self, fuzzer: FuzzManager, proj: project.Project, base_proj: Optional[project.Project], batchsize: Optional[int] = None):
        self.fuzzer = fuzzer
        self.proj = proj
        self.base_proj = base_proj
        super().__init__(batchsize=batchsize)

    async def _handle_work(self, work: list[ProcessFuzzCrashData]) -> list[Result[None]]:
        builds = (await self.proj.build_all()).unwrap()
        harnesses = (await self.proj.init_harness_info()).unwrap()
        if self.base_proj:
            base_builds = (await self.base_proj.build_all()).unwrap()
            _ = (await self.base_proj.init_harness_info()).unwrap()
        else:
            base_builds = None

        # read the files from the workstuff
        def make_runnable_crash_data():
            res: list[Result[tuple[project.Harness, bytes]]] = []
            for w in work:
                try:
                    res.append( Ok((harnesses[w.harness_num], open(w.filename, "rb").read())) )
                except OSError:
                    res.append( Err(CRSError(f"crash file missing {w.filename}")) )
            return res
        runnable_crash_data = await asyncio.to_thread(make_runnable_crash_data)

        crashes: list[tuple[project.Harness, project.CrashResult]] = []
        async with manager.scope(group=DockerGroup.Misc, timeout=BULK_TRIAGE_TIMEOUT) as scope:
            match await project.run_povs_post_acquire(builds, base_builds, scope, [e for e in runnable_crash_data]):
                case Err():
                    # all the work is a failure
                    return [Err(CRSError("bulk pov test operation failed")) for _ in work]
                case Ok(pov_res):
                    res: list[Result[None]] = []
                    # parse each crash data separately
                    for indata, outdata in zip(runnable_crash_data, pov_res):
                        match outdata:
                            case Err() as e:
                                # note we do NOT delete the crash in this path. If it never reproduces, it remains on disk
                                # we may want to do something with it later?
                                res.append(e)
                            case Ok(crash_res):
                                # if our crash reproduces, parse it and do callbacks
                                if crash_res is not None:
                                    crash = self.proj.parse_crash_contents(crash_res[0], indata.unwrap()[1], crash_res[1])
                                    crashes.append((indata.unwrap()[0], crash))
                                res.append(Ok(None))

        # register any crashes we found
        await self.fuzzer.on_crashes(crashes)

        # remove any item we processed
        await batch_unlink(*(w.filename for w in work), missing_ok=True)

        return res

TEST_POV_TIMEOUT = 60 * 60
DEFAULT_TEST_POVS_LIMIT = 32

@requireable
async def _test_povs_on_patch(
    scope: DockerScope,
    tg: LimitedTaskGroup,
    task: project.Task,
    patch: PatchRes,
    povs: list[POVRunData],
    timeout: float = TEST_POV_TIMEOUT
) -> Result[list[bool]]:
    """
    Test all the given patch on all povs in bulk in the given scope, tg

    Return a list of bools, one for each pov.
    True indicates the patch remediates the pov, False indicates otherwise
    """
    artifacts: list[project.BuildArtifacts] = []
    for artifact in patch.artifacts:
        tar = Path(artifact.build_tar_path)
        if not await tar.exists():
            logger.error(f"patch build_tar missing {tar}")
            break
        vfs = await task.tar_fs_from_path(tar)
        artifacts.append(project.BuildArtifacts(project_name=patch.project_name, build_config=artifact.build_config, build_vfs=vfs))

    if len(artifacts) < len(patch.artifacts):
        # patches with missing builds are invalid - we will have logged an error above, so now return False for each pov
        return Ok([False for _ in povs])

    async def test_pov_with_artifacts(pov: POVRunData) -> Result[project.POVRunReturn]:
        async with AsyncExitStack() as stack:
            runners: list[tuple[project.BuildArtifacts, DockerRun]] = [
                (arts, await stack.enter_async_context(arts.run(timeout=timeout, scope=scope)))
                for arts in artifacts
            ]
            return await project.run_pov_first_crash(runners, pov.input, pov.harness)

    tasks = [
        tg.create_task(
            test_pov_with_artifacts(pov),
            name=f"test_pov_with_artifacts({pov.sanitizer}, {pov.harness})"
        )
        for pov in povs
    ]

    return Ok([
        (res.is_ok() and res.unwrap() is None)
        for t in tasks if (res := await t)
    ])

@requireable
async def test_povs_on_patches(task: project.Task, tests: list[tuple[PatchRes, list[POVRunData]]]) -> Result[list[list[bool]]]:
    """
    Test all the given patch, pov pairs in bulk

    Return a nested list of bools with the same shape as {tests}.
    True indicates the patch remediates the pov, False indicates otherwise
    """
    async with manager.scope(group=DockerGroup.Build) as scope:
        async with LimitedTaskGroup(scope.host.cores or DEFAULT_TEST_POVS_LIMIT) as runner_tg:
            async with asyncio.TaskGroup() as tg:
                tasks = [
                    tg.create_task(
                        _test_povs_on_patch(scope, runner_tg, task, patch, povs),
                        name=f"_test_povs_on_patch({patch.project_name}, {len(povs)=})"
                    )
                    for patch, povs in tests
                ]
        results = [require(await t) for t in tasks]
        return Ok(results)



class SpendLimiter:
    def __init__(self, view: CounterView):
        self.view = view
        self.locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @asynccontextmanager
    async def limit(self, var: str, /, max: float, deposit: float):
        with LLMSpendTracker() as tracker:
            refund = 0

            # finalizer to run when exiting the block
            async def update_spend():
                amount = tracker.spend() - refund
                if amount != 0:
                    _ = await self.view.add(var, tracker.spend() - refund)

            async def add_deposit():
                nonlocal refund
                _ = await self.view.add(var, deposit)
                refund = deposit

            async with finalize(update_spend()):
                async with self.locks[var]:
                    if await self.view.get(var) >= max:
                        yield Err(CRSError(f"spend limit exceeded: {var}"))
                        return
                    await shield_and_wait(add_deposit()) # shield the deposit apply so refund always gets set

                yield Ok(None)
