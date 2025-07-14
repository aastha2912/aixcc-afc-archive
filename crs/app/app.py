from collections import defaultdict
from dataclasses import dataclass as py_dataclass
from enum import StrEnum, IntEnum, auto
from pydantic.dataclasses import dataclass
import asyncio
import contextlib
import random
import os
import uuid

from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional, Iterable, TypedDict

from opentelemetry import trace


from crs.config import telem_tracer, metrics, MODEL_MAP
from crs.agents import branch_flipper, diff_analyzer, generate_kaitai, pov_producer, produce_patch, triage, vuln_analyzer, harness_input_decoder
from crs.app import api_task
from crs.app.app_meta import running_crs
from crs.app.helpers import TaskData, BulkCoverageWorker, BulkCrashWorker, CalculateCoverageData, ProcessFuzzCrashData, test_povs_on_patches, SpendLimiter
from crs.app.submitter import Submitter
from crs.app.products_db import ProductsDB, DECODER_TYPE_LOOKUP
from crs.app.counter_db import CounterDB
from crs.app.quantile import QuantileEstimator
from crs.common.alru import alru_cache
from crs.common.types import Coro, CRSError, POVTarget, Result, Ok, Err, Priority, Decoder, DecodedPOV, POVRunData, AnalyzedVuln, PatchRes, VulnReport
from crs.common.latency import async_latency_monitor
from crs.common.utils import only_ok, require, requireable, run_coro_batch, to_tool_result, ExceptAndLogTaskGroup
from crs.common.workdb import WorkDB, WorkDesc
from crs.modules import project, static_analysis, sarif, debugger, coverage, kaitai
from crs.modules.fuzzing import FuzzManager
from crs.task_server import db

from crs.analysis.integration import get_ainalysis_reports

from crs_rust import logger

MAX_DECODER_SEEDS = 32
MAX_HARNESS_PRECOMPUTE = 32
DEFAULT_MAX_DECODERS = 8
DECODER_SEED_DELAY = 60
MAX_SEED_CHECKS = 20
VULN_SCORE_QUANTILE = 0.80 # TODO: tune this
PATCH_DELAY_ALLOWANCE = 120
TASKDB_POLL_PERIOD = 0.1
PING_FAIL_DELAY = 20
EXTRA_POV_COUNT = 10 # if we attempt to pov vuln id N and instead pov id M; try N again up to this many times
NO_POV_PATCH_DELAY = 45 * 60 # if we develop a patch WITHOUT a pov to test, wait this long before submitting
# for every "verified" patch, how many "unverified" patches can we submit
# this number is
UNVERIFIED_PATCH_RATIO = 2.0
GLOBAL_SCORE_THRESHOLD = 0.1

MAX_BRANCH_FLIP_PER_TASK = 100

SpendLimits = TypedDict("SpendLimits", {"max": float, "deposit": float})
SPEND_LIMITS: dict[str, SpendLimits] = {
    'analyze_vuln': {"max": 666, "deposit": 1},
    'patch_vuln': {"max": 666, "deposit": 1},
    'produce_pov': {"max": 666, "deposit": 5},
    'triage_pov': {"max": 500, "deposit": 1},
}

pov_counter = metrics.create_counter("pov")
vuln_counter = metrics.create_counter("vuln")
submission_counter = metrics.create_counter("submission")
patch_counter = metrics.create_counter("patch")
branch_flip_counter = metrics.create_counter("branch_flip")

class VulnSource(StrEnum):
    INFER = "infer"
    AINALYSIS = "ainalysis"
    AINALYSIS_MULTI = "ainalysis_multi"
    DIFF_ANALYZER = "diff_analyzer"
    SARIF = "sarif"
    FUZZING = "fuzzing"

@py_dataclass
class BackgroundWorker:
    fuzzer: FuzzManager
    coverage: BulkCoverageWorker
    fuzzcrash: BulkCrashWorker

class WorkType(IntEnum):
    LAUNCH_TASK = auto()           # start fuzzers, run any applicable analyses
    LAUNCH_TASK_SCOPE = auto()     # hold open a global exit stack scope for the task
    LAUNCH_BUILDS = auto()         # kickoff all useful types of builds
    LAUNCH_BGWORKERS = auto()      # set up the bgworker background structures
    LAUNCH_FUZZERS = auto()        # run fuzzing on a task
    LAUNCH_INFER = auto()          # run infer static analyzer on a task
    LAUNCH_AINALYSIS = auto()      # run LLM-based analysis on a task
    LAUNCH_AINALYSIS_M = auto()    # run LLM-based analysis on a task
    LAUNCH_SARIF = auto()          # kickoff analysis on a sarif broadcast

    ANALYZE_HARNESS = auto()       # kickoff pre-processing agents for a harness
    GENERATE_ENCODER = auto()      # try to generate an input encoder for a harness
    GENERATE_DECODER = auto()      # try to generate an input decoder for a harness
    SCORE_VULN = auto()            # run LLM-based scoring for a candidate vuln
    ANALYZE_DIFF = auto()          # run diff analysis
    ANALYZE_VULN = auto()          # run candidate-vuln analysis

    PROCESS_COVERAGE = auto()      # run a seed to gather coverage
    TRIAGE_FUZZ_CRASH = auto()     # triage a potential crash from a fuzzer
    PRODUCE_POV = auto()           # run produce_pov on a plausible bug description
    PRODUCE_POV_HINT = auto()      # run produce_pov on a plausible bug description and close seed
    PATCH_VULN = auto()            # produce a patch for a working POV
    TRIAGE_POV = auto()            # triage a POV from fuzzer

    PRE_FLIP_BRANCH = auto()       # run a branch flipper for frontiers
    FLIP_BRANCH = auto()           # run a branch flipper for frontiers

    BUNDLE_POV = auto()            # compute patch matrix for pov, assign it to a bundle
    BUNDLE_PATCH = auto()          # compute patch matrix for patch, assign it to a bundle
    BUNDLE_PATCH_NO_POV = auto()   # consider a patch for scoring after a delay
    BUNDLE_SARIF = auto()          # assign a sarif to a bundle
    SUBMIT_BUNDLE = auto()         # submit all data for a given bundle

@dataclass(slots=True)
class TaskDataHarnesses(TaskData):
    harnesses_included: bool

@dataclass(slots=True)
class HarnessData(TaskData):
    harness_num: int

@dataclass(slots=True)
class CoderRequestData(HarnessData):
    decoder_type: Optional[str]
    cur_count: int # current number of coders of the given type, used to dedupe requests

@dataclass(slots=True)
class SARIFData(TaskData):
    sarif_id: uuid.UUID
    sarif: dict[str, Any]

@dataclass(slots=True)
class ReportData(TaskData):
    report_id: int

@dataclass(slots=True)
class VulnData:
    vuln_id: int

@dataclass(slots=True)
class PatchVulnData(VulnData):
    pov_ids: Optional[list[int]]

@dataclass(slots=True)
class POVData:
    pov_id: int

@dataclass(slots=True)
class BranchFlipData(TaskData):
    frontier: coverage.Frontier

@dataclass(slots=True)
class PreBranchFlipData(BranchFlipData):
    submission_time: datetime

@dataclass(slots=True)
class TriageData(POVData):
    source: VulnSource
    expected: Optional[int] = None

@dataclass(slots=True)
class PatchData:
    patch_id: int
    pov_verified: bool

@dataclass(slots=True)
class DelayPatchData:
    patch_id: int
    deadline: datetime

@dataclass(slots=True)
class SARIFAssessmentData(TaskData):
    vuln_id: int
    sarif_id: uuid.UUID

@dataclass(slots=True)
class BundleData(TaskData):
    vuln_id: int

class CRSWorkDB(WorkDB[WorkType]):
    WORK_DESCS: dict[WorkType, WorkDesc[Any]] = {
        WorkType.LAUNCH_TASK:         WorkDesc(limit=   64, timeout=float('inf'), cls=TaskDataHarnesses, attempts=None),
        WorkType.LAUNCH_TASK_SCOPE:   WorkDesc(limit=   64, timeout=float('inf'), cls=TaskData, attempts=None),
        WorkType.LAUNCH_BGWORKERS:    WorkDesc(limit=   64, timeout=float('inf'), cls=TaskData, attempts=None),
        WorkType.LAUNCH_BUILDS:       WorkDesc(limit=    8, timeout=float('inf'), cls=TaskData),
        WorkType.LAUNCH_FUZZERS:      WorkDesc(limit=   64, timeout=float('inf'), cls=TaskData, attempts=None),
        WorkType.LAUNCH_INFER:        WorkDesc(limit=   12, timeout=float('inf'), cls=TaskData),
        WorkType.LAUNCH_AINALYSIS:    WorkDesc(limit=    4, timeout=float('inf'), cls=TaskData),
        WorkType.LAUNCH_AINALYSIS_M:  WorkDesc(limit=    4, timeout=float('inf'), cls=TaskData),
        WorkType.LAUNCH_SARIF:        WorkDesc(limit=   50, timeout=float('inf'), cls=SARIFData),
        WorkType.GENERATE_ENCODER:    WorkDesc(limit=   64, timeout=60 * 60,      cls=CoderRequestData),
        WorkType.GENERATE_DECODER:    WorkDesc(limit=   64, timeout=60 * 60,      cls=CoderRequestData),
        WorkType.ANALYZE_HARNESS:     WorkDesc(limit=   32, timeout=2 * 60 * 60,  cls=HarnessData),
        WorkType.ANALYZE_DIFF:        WorkDesc(limit=   32, timeout=float('inf'), cls=TaskData, attempts=6),
        WorkType.ANALYZE_VULN:        WorkDesc(limit= 1000, timeout=float('inf'), cls=ReportData),
        WorkType.PRODUCE_POV:         WorkDesc(limit=   50, timeout=2 * 60 * 60,  cls=VulnData), # pov producer
        WorkType.PRODUCE_POV_HINT:    WorkDesc(limit=   50, timeout=2 * 60 * 60,  cls=VulnData), # pov producer
        WorkType.SCORE_VULN:          WorkDesc(limit= 1000, timeout=2 * 60 * 60,  cls=ReportData), # vuln scorer
        WorkType.PATCH_VULN:          WorkDesc(limit=   32, timeout=2 * 60 * 60,  cls=PatchVulnData, attempts=5), # patching
        WorkType.TRIAGE_POV:          WorkDesc(limit=  100, timeout=60 * 60,      cls=TriageData), # bug triage
        WorkType.BUNDLE_POV:          WorkDesc(limit=   15, timeout=60 * 60,      cls=POVData, attempts=10), # bundle new POV
        WorkType.BUNDLE_PATCH:        WorkDesc(limit=   15, timeout=60 * 60,      cls=PatchData, attempts=10), # bundle new patch
        WorkType.BUNDLE_PATCH_NO_POV: WorkDesc(limit=  500, timeout=60 * 60,      cls=DelayPatchData, attempts=10), # bundle new patch
        WorkType.BUNDLE_SARIF:        WorkDesc(limit=   15, timeout=60 * 60,      cls=SARIFAssessmentData, attempts=10), # bundle new SARIF
        WorkType.SUBMIT_BUNDLE:       WorkDesc(limit=  200, timeout=60 * 60,      cls=BundleData, attempts=None), # submit data for a bundle
        WorkType.PRE_FLIP_BRANCH:     WorkDesc(limit= 2000, timeout=2 * 60 * 60,  cls=PreBranchFlipData), # branch flipper pre-checks
        WorkType.FLIP_BRANCH:         WorkDesc(limit=   10, timeout=2 * 60 * 60,  cls=BranchFlipData, attempts=1), # branch flipper

        # bulk coverage
        WorkType.PROCESS_COVERAGE: WorkDesc(
            limit=3_000,
            batchsize=500,
            timeout=60 * 60,
            cls=CalculateCoverageData,
            silent=True,
        ),
        # bulk crash handling
        WorkType.TRIAGE_FUZZ_CRASH: WorkDesc(
            limit=500,
            batchsize=100,
            timeout=60 * 60,
            cls=ProcessFuzzCrashData,
            silent=True,
        ),
    }

class CRS:
    def __init__(self):
        self.taskdb = db.TaskDB()
        self.workdb = CRSWorkDB(WorkType)
        self.productsdb = ProductsDB()
        self.counterdb = CounterDB()
        self.bgworkers_waiting: dict[project.Task, asyncio.Event] = defaultdict(asyncio.Event)
        self.bgworkers: dict[project.Task, BackgroundWorker] = {}
        self.submitter = Submitter(db=self.productsdb)
        self.vuln_quantiles: dict[uuid.UUID, QuantileEstimator] = {}
        self.spend_limiters: dict[uuid.UUID, SpendLimiter] = {}
        self.exit_stacks: dict[uuid.UUID, contextlib.AsyncExitStack] = {}

        self.workdb.register_work_callback(WorkType.LAUNCH_TASK, self.launch_task)
        self.workdb.register_work_callback(WorkType.LAUNCH_TASK_SCOPE, self.launch_task_scope)
        self.workdb.register_work_callback(WorkType.LAUNCH_BUILDS, self.launch_builds)
        self.workdb.register_work_callback(WorkType.LAUNCH_BGWORKERS, self.launch_bgworkers)
        self.workdb.register_work_callback(WorkType.LAUNCH_FUZZERS, self.launch_fuzzers)
        self.workdb.register_work_callback(WorkType.LAUNCH_INFER, self.launch_infer)
        self.workdb.register_work_callback(WorkType.LAUNCH_AINALYSIS, self.launch_ainalysis)
        self.workdb.register_work_callback(WorkType.LAUNCH_AINALYSIS_M, lambda w: self.launch_ainalysis(w, multi=True))
        self.workdb.register_work_callback(WorkType.LAUNCH_SARIF, self.launch_sarif)
        self.workdb.register_work_callback(WorkType.ANALYZE_HARNESS, self.analyze_harness)
        self.workdb.register_work_callback(WorkType.GENERATE_ENCODER, self.generate_encoder)
        self.workdb.register_work_callback(WorkType.GENERATE_DECODER, self.generate_decoder)
        self.workdb.register_work_callback(WorkType.SCORE_VULN, self.score_vuln)
        self.workdb.register_work_callback(WorkType.ANALYZE_DIFF, self.analyze_diff)
        self.workdb.register_work_callback(WorkType.ANALYZE_VULN, self.analyze_vuln)
        self.workdb.register_work_callback(WorkType.PRODUCE_POV, self.produce_pov)
        self.workdb.register_work_callback(WorkType.PRODUCE_POV_HINT, self.produce_pov_if_hit)
        self.workdb.register_work_callback(WorkType.PATCH_VULN, self.patch_vuln)
        self.workdb.register_work_callback(WorkType.TRIAGE_POV, self.triage_pov)
        self.workdb.register_work_callback(WorkType.PROCESS_COVERAGE, self.process_coverage)
        self.workdb.register_work_callback(WorkType.TRIAGE_FUZZ_CRASH, self.process_crash)
        self.workdb.register_work_callback(WorkType.BUNDLE_POV, self.bundle_pov)
        self.workdb.register_work_callback(WorkType.BUNDLE_PATCH, self.bundle_patch)
        self.workdb.register_work_callback(WorkType.BUNDLE_PATCH_NO_POV, self.bundle_patch_no_pov)
        self.workdb.register_work_callback(WorkType.BUNDLE_SARIF, self.bundle_sarif)
        self.workdb.register_work_callback(WorkType.SUBMIT_BUNDLE, self.submit_bundle)
        self.workdb.register_work_callback(WorkType.PRE_FLIP_BRANCH, self.pre_flip_branch)
        self.workdb.register_work_callback(WorkType.FLIP_BRANCH, self.flip_branch)

        self.dupe_locks: defaultdict[uuid.UUID, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.encoder_locks: defaultdict[tuple[Optional[type[Decoder]], uuid.UUID, int], asyncio.Lock] = defaultdict(asyncio.Lock)
        self.decoder_locks: defaultdict[tuple[type[Decoder], uuid.UUID, int], asyncio.Lock] = defaultdict(asyncio.Lock)
        self.bundle_conds: defaultdict[uuid.UUID, asyncio.Condition] = defaultdict(asyncio.Condition)

    async def wait_for_bgworker(self, task: project.Task):
        if task not in self.bgworkers:
            logger.info("waiting for task in bgworkers...")
            try:
                _ = await self.bgworkers_waiting[task].wait()
            finally:
                logger.info("waiting for task in bgworkers... done!")
                _ = self.bgworkers_waiting.pop(task, None)

    @alru_cache(maxsize=32, filter=only_ok)
    async def _task_from_id(self, task_id: uuid.UUID) -> Result[project.Task]:
        dbtask = await self.taskdb.get_task(task_id)
        if dbtask is None:
            return Err(CRSError(f"missing task data for task with {task_id=}"))
        return await api_task.api_to_crs_task(dbtask)

    async def task_from_id(self, task_id: uuid.UUID) -> Result[project.Task]:
        task = await self._task_from_id(task_id)
        match task:
            case Ok(t):
                span = trace.get_current_span()
                if span == trace.INVALID_SPAN and os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
                    logger.error("invalid span in CRS:task_from_id")
                span.set_attributes(t.metadata)
                span.set_attribute("crs.debug.target.project.name", t.project.name)
            case _:
                pass
        return task

    @telem_tracer.start_as_current_span(
        "crs_task.patch_vuln",
        attributes={"crs.action.category": "patch_generation", "crs.action.name": "crs_task.patch_vuln"}
    )
    @requireable
    async def patch_vuln(self, data: PatchVulnData) -> Result[None]:
        row = await self.productsdb.get_vuln(data.vuln_id)
        if not row:
            return Err(CRSError(f"missing vuln for id {data.vuln_id}"))

        task_id, _, vuln = row
        task = require(await self.task_from_id(task_id))

        # grab specific pov_ids if given, otherwise grab all for the vuln_id
        if data.pov_ids is not None:
            povs: list[POVRunData] = []
            for pov_id in data.pov_ids:
                pov = await self.productsdb.get_pov(pov_id)
                if pov is None:
                    return Err(CRSError(f"{pov_id=} does not exist"))
                povs.append(pov)
        else:
            povs = list((await self.productsdb.get_povs_for_vuln(data.vuln_id)).values())

        harnesses = require(await task.project.init_harness_info())
        decoded = [(await self.decode_pov(task, harnesses, pov))[0] for pov in povs]

        limiter = self._get_spend_limiter(task)
        async with limiter.limit("patch_vuln", **SPEND_LIMITS["patch_vuln"]) as res:
            require(res) # ensure we're allow to spend

            coros = [
                produce_patch.CRSPatcher.from_task(task).patch_vulnerability(vuln, decoded, rawdiff=False),
                produce_patch.CRSPatcher.from_task(task).patch_vulnerability(vuln, decoded, rawdiff=True)
            ]
            def stop_condition(response: Result[produce_patch.PatchResult]):
                match response:
                    case Ok(produce_patch.ConfirmedPatchResult()):
                        return True
                    case _:
                        return False
            responses = await run_coro_batch(
                coros,
                name=f"produce_patch() project={task.project.name}",
                stop_condition=stop_condition
            )

        errs: list[CRSError] = []
        success = False
        for response in responses:
            this_success = False
            match response:
                case Ok(produce_patch.ConfirmedPatchResult() as res):
                    patch_res = PatchRes(
                        task_uuid=task_id,
                        project_name=task.project.name,
                        diff=res.patch,
                        vuln_id=data.vuln_id,
                        artifacts=res.build_artifacts
                    )
                    patch_id = await self.productsdb.add_patch(patch_res)
                    if povs:
                        await self.workdb.submit_job(
                            task.task_id,
                            WorkType.BUNDLE_PATCH,
                            PatchData(patch_id=patch_id, pov_verified=True),
                            task.deadline_datetime
                        )
                    else:
                        consider_at = datetime.now(timezone.utc) + timedelta(seconds=NO_POV_PATCH_DELAY)
                        await self.workdb.submit_job(
                            task.task_id,
                            WorkType.BUNDLE_PATCH_NO_POV,
                            DelayPatchData(patch_id=patch_id, deadline=consider_at),
                            task.deadline_datetime
                        )
                    success = True
                    this_success = True
                case Err() as e:
                    errs.append(CRSError(f"patcher failed: {e}"))
                case Ok(res):
                    errs.append(CRSError(f"patch result wasn't confirmed: {res}"))
            patch_counter.add(1, {
                "task": str(task_id),
                "project": task.project.name,
                "success": "1" if this_success else "0",
            })
        if success:
            return Ok(None)
        return Err(CRSError(f"patch batch failed - errors:\n{'\n'.join(e.error for e in errs)}"))

    @telem_tracer.start_as_current_span(
        "crs_task.process_coverage",
        attributes={"crs.action.category": "dynamic_analysis", "crs.action.name": "crs_task.process_coverage"},
        record_exception=False
    )
    @requireable
    async def process_coverage(self, cov_dat: CalculateCoverageData) -> Result[None]:
        task = require(await self.task_from_id(cov_dat.task_id))
        await self.wait_for_bgworker(task)
        return await self.bgworkers[task].coverage.enqueue_and_wait(cov_dat)

    @telem_tracer.start_as_current_span(
        "crs_task.process_fuzzer_crash",
        attributes={"crs.action.category": "dynamic_analysis", "crs.action.name": "crs_task.process_fuzzer_crash"},
        record_exception=False
    )
    @requireable
    async def process_crash(self, crash_dat: ProcessFuzzCrashData) -> Result[None]:
        task = require(await self.task_from_id(crash_dat.task_id))
        await self.wait_for_bgworker(task)
        return await self.bgworkers[task].fuzzcrash.enqueue_and_wait(crash_dat)

    async def launch_task_scope(self, task_data: TaskData) -> Result[None]:
        async with contextlib.AsyncExitStack() as stack:
            self.exit_stacks[task_data.task_id] = stack
            try:
                while True:
                    await asyncio.sleep(float('inf'))
            finally:
                _ = self.exit_stacks.pop(task_data.task_id, None)

    @telem_tracer.start_as_current_span(
        "crs_task.launch_bgworkers",
        attributes={"crs.action.name": "crs_task.launch_bgworkers"},
        record_exception=False
    )
    @requireable
    async def launch_bgworkers(self, task_data: TaskData) -> Result[None]:
        task = require(await self.task_from_id(task_data.task_id))
        fuzzer = FuzzManager(task)
        async def handle_frontier(frontiers: list[coverage.Frontier]):
            dt_now = datetime.now(timezone.utc)
            for frontier in frontiers:
                await self.workdb.submit_job(
                    task.task_id,
                    WorkType.PRE_FLIP_BRANCH,
                    PreBranchFlipData(task_id=task_data.task_id, frontier=frontier, submission_time=dt_now),
                    expiration=task.deadline_datetime,
                    priority=(1 - 1 / max(1, frontier.score)) * Priority.LOW,
                )

        if isinstance(task, project.DeltaTask):
            base = task.base
        else:
            base = None

        coverage_desc = self.workdb.WORK_DESCS[WorkType.PROCESS_COVERAGE]
        crash_desc = self.workdb.WORK_DESCS[WorkType.TRIAGE_FUZZ_CRASH]
        workers = self.bgworkers[task] = BackgroundWorker(
            fuzzer,
            coverage=BulkCoverageWorker(fuzzer, task.coverage, handle_frontier, batchsize=coverage_desc.batchsize),
            fuzzcrash=BulkCrashWorker(fuzzer, task.project, base, batchsize=crash_desc.batchsize),
        )
        if task in self.bgworkers_waiting:
            self.bgworkers_waiting[task].set()

        async def triage_fuzz_crash(harness_id: int, filename: str):
            await self.workdb.submit_job(
                task.task_id,
                WorkType.TRIAGE_FUZZ_CRASH,
                ProcessFuzzCrashData(task_id=task_data.task_id, harness_num=harness_id, filename=filename),
                expiration=task.deadline_datetime
            )
        fuzzer.add_triage_callback(triage_fuzz_crash)

        async def register_crashes(crashes: Iterable[tuple[POVTarget, project.CrashResult, bool]]):
            # ignore any old crashes
            new_crashes = [(target, crash) for target,crash,is_new in crashes if is_new]
            pov_ids = await self.productsdb.add_povs([
                POVRunData(
                    task_uuid=target.task_uuid,
                    project_name=target.project_name,
                    harness=target.harness,
                    sanitizer=target.sanitizer,
                    engine=target.engine,
                    python=None,
                    input=crash.input,
                    output=crash.output,
                    dedup=crash.dedup,
                    stack=crash.stack
                ) for target,crash in new_crashes
            ])
            _ = await asyncio.gather(*[
                self.workdb.submit_job(
                    task.task_id,
                    WorkType.TRIAGE_POV,
                    TriageData(pov_id=pov_id, source=VulnSource.FUZZING),
                    expiration=task.deadline_datetime,
                    priority=Priority.CRITICAL
                ) for pov_id in pov_ids
            ])
        fuzzer.add_crash_callback(register_crashes)

        async def add_coverage(harness_id: int, filename: str):
            remaining = (task.deadline_datetime - datetime.now(timezone.utc)).total_seconds()
            await self.workdb.submit_job(
                task.task_id,
                WorkType.PROCESS_COVERAGE,
                CalculateCoverageData(task_id=task_data.task_id, harness_num=harness_id, filename=filename),
                expiration=task.deadline_datetime,
                priority=Priority.MEDIUM + (remaining/50_000), # force newer seeds to be higher priority than older ones
            )
        fuzzer.add_seed_callback(add_coverage)

        try:
            await self.workdb.submit_job(
                task.task_id,
                WorkType.LAUNCH_FUZZERS,
                TaskData(task_id=task.task_id),
                expiration=task.deadline_datetime,
                unique=True,
            )
            async with task.coverage.db.sqlite_pin(), asyncio.TaskGroup() as tg:
                async def retry_loop(fn: Callable[[], Awaitable[None]]):
                    while True:
                        try:
                            await fn()
                        except Exception:
                            logger.exception("bgworker exception, sleeping 2s")
                            await asyncio.sleep(2)

                _ = tg.create_task(retry_loop(workers.coverage.run), name=f"launch_bgworkers() -> workers.coverage.run() project={task.project.name}")
                _ = tg.create_task(retry_loop(workers.fuzzcrash.run), name=f"launch_bgworkers() -> workers.fuzzcrash.run() project={task.project.name}")
            return Ok(None)
        finally:
            _ = self.bgworkers.pop(task, None)

    @telem_tracer.start_as_current_span(
        "crs_task.launch_fuzzers",
        attributes={"crs.action.category": "fuzzing", "crs.action.name": "crs_task.launch_fuzzers"},
        record_exception=False
    )
    @requireable
    async def launch_fuzzers(self, task_data: TaskData) -> Result[None]:
        task = require(await self.task_from_id(task_data.task_id))

        await self.wait_for_bgworker(task)
        fuzzer = self.bgworkers[task].fuzzer

        # TODO: add a seed callback periodically regenerate decoders?

        loop = asyncio.get_running_loop()
        end_time = (task.deadline_datetime - datetime.now(timezone.utc)).total_seconds()
        loop_deadline = loop.time() + end_time

        try:
            async with asyncio.timeout_at(loop_deadline):
                await fuzzer.run()
        except TimeoutError:
            pass
        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.launch_ainalysis",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.launch_ainalysis"},
        record_exception=False
    )

    @requireable
    async def launch_ainalysis(self, task_data: TaskData, multi: bool = False) -> Result[None]:
        task = require(await self.task_from_id(task_data.task_id))
        model_map = MODEL_MAP.get()
        models = model_map.get("FullMode" + ("Multi" if multi else ""), []) or []

        async def run_model(model: str) -> bool:
            try:
                match await get_ainalysis_reports(task, model, multi=multi):
                    case Ok(reports):
                        pass
                    case Err(e):
                        logger.exception(f"ainalysis failed on {task.project.name}:{task.task_id}", exc=e)
                        return False
                source = VulnSource.AINALYSIS_MULTI if multi else VulnSource.AINALYSIS
                report_ids = await self.productsdb.add_reports(
                    VulnReport(
                        task_uuid=task.task_id,
                        project_name=task.project.name,
                        function=report.function,
                        file=report.file,
                        description=report.description,
                        source=source,
                        sarif_id=None,
                        function_range=report.function_range
                    ) for report in reports
                )
                _ = await asyncio.gather(
                    *(self.workdb.submit_job(
                        task.task_id,
                        WorkType.SCORE_VULN,
                        ReportData(
                            task_id=task.task_id,
                            report_id=report_id
                        ),
                        task.deadline_datetime,
                    ) for report_id in report_ids))
                return True
            except Exception as e:
                logger.exception(f"ainalysis failed on {task.project.name}:{task.task_id}", exc=e)
                return False

        tasks: set[asyncio.Task[bool]] = set()
        success = False
        async with asyncio.TaskGroup() as tg:
            for model in models:
                tasks.add(
                    tg.create_task(run_model(model), name=f"ainalysis({task_data.task_id}, {multi})")
                )
            for t in tasks:
                if await t:
                    success = True

        if success:
            return Ok(None)
        return Err(CRSError("ainalysis failed to produce any results"))

    @telem_tracer.start_as_current_span(
        "crs_task.launch_infer",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.launch_infer"},
        record_exception=False
    )
    @requireable
    async def launch_infer(self, task_data: TaskData) -> Result[None]:
        task = require(await self.task_from_id(task_data.task_id))
        _ = require(await task.project.init_harness_info())

        logger.info(f"running infer on {task.task_id=} {task.project.name=}")
        analyzer = static_analysis.StaticAnalyzer(task)
        vuln_reports = require(await analyzer.get_infer_vuln_reports())
        report_ids = await self.productsdb.add_reports(
            VulnReport(
                task_uuid=task.task_id,
                project_name=task.project.name,
                function=report.function,
                file=report.file,
                description=report.description,
                source=VulnSource.INFER,
                sarif_id=None,
                function_range=report.function_range
            ) for report in vuln_reports
        )
        _ = await asyncio.gather(
            *(self.workdb.submit_job(
                task.task_id,
                WorkType.SCORE_VULN,
                ReportData(
                    task_id=task.task_id,
                    report_id=report_id
                ),
                task.deadline_datetime,
            ) for report_id in report_ids))
        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.launch_sarif",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.launch_sarif"},
        record_exception=False
    )
    @requireable
    async def launch_sarif(self, data: SARIFData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))

        report = await sarif.sarif_to_vuln_report(task, data.sarif)

        # do a quick first pass by deduping it against our known vulns
        # we may update this assessment later after full analysis
        vuln = AnalyzedVuln(
            function=report.function,
            file=report.file,
            description=report.description,
            conditions="unknown"
        )
        try:
            # note: any unwrap exception will be caught below
            _, new = (await self.dedupe_vuln(task, VulnSource.SARIF, vuln, add_if_new=False)).unwrap()
            correct = not new
            reason = "appears to be a new vuln" if new else "matched known vuln"
            _ = await self.submitter.submit_sarif_assessment(task.task_id, None, data.sarif_id, correct, reason)
            submission_counter.add(1, {
                "task": str(task.task_id),
                "project": task.project.name,
                "type": "sarif",
            })
        except Exception as e:
            logger.error(f"error submitting initial sarif assessment for {data.sarif_id}: {repr(e)}")

        report_id, = await self.productsdb.add_reports([
            VulnReport(
                task_uuid=task.task_id,
                project_name=task.project.name,
                function=report.function,
                file=report.file,
                description=report.description,
                source=VulnSource.SARIF,
                sarif_id=data.sarif_id,
                function_range=report.function_range
            )
        ])
        # skip scoring, go straight to analysis with highest priority
        await self.workdb.submit_job(
            task.task_id,
            WorkType.ANALYZE_VULN,
            ReportData(
                task_id=task.task_id,
                report_id=report_id
            ),
            task.deadline_datetime,
            priority=Priority.CRITICAL
        )
        return Ok(None)

    def _get_vuln_quantile_estimator(self, task: project.Task) -> QuantileEstimator:
        if task.task_id not in self.vuln_quantiles:
            self.vuln_quantiles[task.task_id] = QuantileEstimator(
                self.counterdb.view(str(task.task_id)+"-vuln-scores-quantile"),
                VULN_SCORE_QUANTILE
            )
        return self.vuln_quantiles[task.task_id]

    @telem_tracer.start_as_current_span(
        "crs_task.score_vuln",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.score_vuln"},
        record_exception=False
    )
    @requireable
    async def score_vuln(self, data: ReportData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))
        report = await self.productsdb.get_report(data.report_id)
        if report is None:
            return Err(CRSError(f"report_id {data.report_id} does not exist"))
        crs = vuln_analyzer.CRSVuln.from_task(task)
        score = require(await crs.score_vuln_report(report)).overall()

        logger.info(f"Report {data.report_id} score: {score}")
        quantile = self._get_vuln_quantile_estimator(task)
        # check if it's above task quantile threashold AND the global one
        if await quantile.add(score) and score > GLOBAL_SCORE_THRESHOLD:
            await self.workdb.submit_job(
                task.task_id,
                WorkType.ANALYZE_VULN,
                data,
                task.deadline_datetime,
                (1 - score) * Priority.HIGH
            )
        return Ok(None)

    async def get_seeds(self, task: project.Task, harness_num: int, max_seeds: int):
        await self.wait_for_bgworker(task)
        return await self.bgworkers[task].fuzzer.get_corpus_by_num(harness_num, max_seeds)

    @requireable
    async def _generate_decoder(
        self,
        task: project.Task,
        harness_num: int,
        decoder_type: type[Decoder],
        max_seeds: int = MAX_DECODER_SEEDS
    ) -> Result[Decoder]:
        """
        Generate a new decoder for harness_num and store it in the DB
        """
        seeds = require(await self.get_seeds(task, harness_num, max_seeds))
        for _ in range(MAX_SEED_CHECKS):
            if len(seeds) > 0:
                break
            logger.warning("No seeds available to generate decoder, delaying for a bit")
            await asyncio.sleep(DECODER_SEED_DELAY)
            seeds = require(await self.get_seeds(task, harness_num, max_seeds))
        if len(seeds) == 0:
            return Err(CRSError("no seeds to use for decoder generation"))

        match decoder_type:
            case kaitai.KaitaiParser:
                logger.info(f"generating kaitai decoder for {task.task_id=} {task.project.name=} {harness_num=}")
                res = await generate_kaitai.CRSGenerateKaitai.from_task(task).generate_kaitai(harness_num, seeds)
            case harness_input_decoder.PythonHarnessInputDecoder:
                logger.info(f"generating python input decoder for {task.task_id=} {task.project.name=} {harness_num=}")
                res = await harness_input_decoder.CRSHarnessInputDecoder.from_task(task).generate_decoder(harness_num, seeds)
            case _:
                logger.info(f"unknown decoder type: {decoder_type}")
                res = Err(CRSError(f"Unknown decoder type: {decoder_type}"))

        match res:
            case Ok(decoder):
                _ = await self.productsdb.add_decoder(task.task_id, task.project.name, harness_num, decoder)
            case _:
                pass
        return res

    async def get_decoders(
        self,
        task: project.Task,
        harness_num: int,
        decoder_type: type[Decoder],
        generate: bool = True,
        max_seeds: int = MAX_DECODER_SEEDS
    ) -> Result[list[Decoder]]:
        async with self.decoder_locks[(decoder_type, task.task_id, harness_num)]:
            existing = await self.productsdb.get_decoders(cls=decoder_type, task_uuid=task.task_id, harness_num=harness_num)
            if len(existing) == 0:
                if not generate:
                    return Ok([])
                match await self._generate_decoder(task, harness_num, decoder_type, max_seeds=max_seeds):
                    case Err() as e:
                        return e
                    case Ok(d):
                        return Ok([d])
            return Ok(existing[::-1])

    async def get_decoder(
        self,
        task: project.Task,
        harness_num: int,
        decoder_type: type[Decoder],
        generate: bool = True,
        max_seeds: int = MAX_DECODER_SEEDS
    ):
        match await self.get_decoders(task, harness_num, decoder_type, generate=generate, max_seeds=max_seeds):
            case Ok([d, *_]):
                return Ok(d)
            case Err() as e:
                return e
            case _:
                return Err(CRSError("no decoders available"))

    async def decode_pov(self, task: project.Task, harnesses: list[project.Harness], pov: POVRunData, try_keep_raw: bool = False) -> tuple[DecodedPOV, Optional[Decoder]]:
        for harness_num, harness in enumerate(harnesses):
            if harness.name == pov.harness:
                break
        else:
            logger.warning(f"no harness found with name = {pov.harness}, cannot use smart decoders")
            return pov.safe_decode(), None

        # try to give a intelligently decoded pov if possible
        decoder_types = [harness_input_decoder.PythonHarnessInputDecoder]
        decoded: Optional[DecodedPOV] = None
        decoder: Optional[Decoder] = None
        for decoder_type in decoder_types:
            match await self.get_decoders(task, harness_num, decoder_type=decoder_type, generate=False):
                case Ok(decoders): pass
                case Err(_):
                    logger.warning(f"Error getting decoders of type {decoder_type}")
                    continue
            for decoder in decoders:
                match await pov.decode(decoder=decoder, try_keep_raw=try_keep_raw):
                    case Ok(decoded): break
                    case _: pass # TODO: can we mark this decoder as failing so we can try to regnerate it?
            else:
                continue
            break
        if decoded is None:
            logger.warning(f"no successful decoding for pov, falling back to safe decoding")
            # fallback to using safe decoding (always succeeds)
            decoded = pov.safe_decode()
        return decoded, decoder

    async def _generate_encoder(
        self,
        task: project.Task,
        harness_num: int,
        decoder_type: Optional[type[Decoder]] = None
    ):
        """
        Generate a new input encoder for harness_num and store it in the DB
        """
        logger.info(f"generating harness input encoder for {task.task_id=} {task.project.name=} {harness_num=} {decoder_type=}")
        decoder = (await self.get_decoder(task, harness_num, decoder_type=decoder_type)).unwrap_or(None) if decoder_type else None
        res = await pov_producer.CRSPovProducer.from_task(task).generate_harness_input_encoder(harness_num, decoder=decoder)
        match res:
            case Ok(encoder):
                _ = await self.productsdb.add_encoder(
                    task.task_id,
                    task.project.name,
                    harness_num,
                    encoder,
                    decoder.__class__ if decoder else None
                )
            case _:
                pass
        return res

    async def get_encoder(self, task: project.Task, harness_num: int, decoder_type: Optional[type[Decoder]]):
        async with self.encoder_locks[(decoder_type, task.task_id, harness_num)]:
            existing = await self.productsdb.get_encoders(task_uuid=task.task_id, harness_num=harness_num, decoder_type=decoder_type)
            if len(existing) == 0:
                # use decoder info if available and requested
                return await self._generate_encoder(task, harness_num, decoder_type=decoder_type)
            # always return latest one
            return Ok(existing[-1])

    @requireable
    async def generate_decoder(self, data: CoderRequestData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))
        if data.decoder_type is None:
            logger.warning("generate_decoder: nothing to do for decoder_type=None")
            return Ok(None)
        decoder_type = DECODER_TYPE_LOOKUP[data.decoder_type]
        async with self.decoder_locks[(decoder_type, task.task_id, data.harness_num)]:
            decoders = await self.productsdb.get_decoders(task_uuid=task.task_id, harness_num=data.harness_num, cls=decoder_type)
            if len(decoders) < data.cur_count:
                logger.info("skipping generate_decoder because decoder count has changed")
                return Ok(None)
            match await self._generate_decoder(task, data.harness_num, decoder_type=decoder_type):
                case Ok(_):
                    return Ok(None)
                case Err(_) as e:
                    return e

    @requireable
    async def generate_encoder(self, data: CoderRequestData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))
        decoder_type = DECODER_TYPE_LOOKUP[data.decoder_type] if data.decoder_type else None
        async with self.encoder_locks[(decoder_type, task.task_id, data.harness_num)]:
            encoders = await self.productsdb.get_encoders(task_uuid=task.task_id, harness_num=data.harness_num, decoder_type=decoder_type)
            if len(encoders) < data.cur_count:
                logger.info("skipping generate_encoder because encoder count has changed")
                return Ok(None)
            match await self._generate_encoder(task, data.harness_num, decoder_type=decoder_type):
                case Ok(_):
                    return Ok(None)
                case Err(_) as e:
                    return e

    @telem_tracer.start_as_current_span(
        "crs_task.analyze_harness",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.analyze_harness"},
        record_exception=False
    )
    @requireable
    async def analyze_harness(self, harness_data: HarnessData) -> Result[None]:
        task = require(await self.task_from_id(harness_data.task_id))
        _ = require(await task.project.init_harness_info()) # ensure harnesses are initialized

        async def start_job(type: WorkType, decoder_type: Optional[type[Decoder]]):
            return await self.workdb.submit_job(
                task.task_id,
                type,
                CoderRequestData(
                    task_id=task.task_id,
                    harness_num=harness_data.harness_num,
                    decoder_type=decoder_type.__name__ if decoder_type else None,
                    cur_count=0
                ),
                task.deadline_datetime,
                unique=True,
            )

        work_types = [
            (WorkType.GENERATE_ENCODER, None),
            (WorkType.GENERATE_DECODER, harness_input_decoder.PythonHarnessInputDecoder),
            (WorkType.GENERATE_ENCODER, harness_input_decoder.PythonHarnessInputDecoder),
        ]
        _ = await asyncio.gather(*(start_job(typ, arg) for typ, arg in work_types))

        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.analyze_diff",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.analyze_diff"},
        record_exception=False
    )
    @requireable
    async def analyze_diff(self, task_data: TaskData) -> Result[None]:
        task = require(await self.task_from_id(task_data.task_id))

        success = False
        # run both with and without pruning; don't bother to terminate early if one succeeds
        for response in await run_coro_batch(
            [diff_analyzer.CRSDiff.from_task(task).analyze_diff(), diff_analyzer.CRSDiff.from_task(task).analyze_diff(rawdiff=True)],
            name=f"analyze_diff() project={task.project.name}"
        ):
            match response:
                case Err(e):
                    logger.error(f"failed to analyze task!: {e}")
                case Ok(res):
                    for vuln in res.vuln:
                        _ = await self.handle_analyzed_vuln(task, VulnSource.DIFF_ANALYZER, vuln)
                        success = True
        if success:
            return Ok(None)
        return Err(CRSError("no bugs found in diff"))

    def _get_spend_limiter(self, task: project.Task) -> SpendLimiter:
        if task.task_id not in self.spend_limiters:
            self.spend_limiters[task.task_id] = SpendLimiter(self.counterdb.view(str(task.task_id)+"-spend-limiter"))
        return self.spend_limiters[task.task_id]

    @telem_tracer.start_as_current_span(
        "crs_task.analyze_vuln",
        attributes={"crs.action.category": "static_analysis", "crs.action.name": "crs_task.analyze_vuln"},
        record_exception=False
    )
    @requireable
    async def analyze_vuln(self, data: ReportData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))
        report = await self.productsdb.get_report(data.report_id)
        if report is None:
            return Err(CRSError(f"report_id {data.report_id} does not exist"))
        assert report.source is not None, "source must be set in db"

        # should never be more than a few models set, but model_idx is taken mod len(models)
        model_idx = random.randint(0, 15)

        # run the analyzer with a spend limit
        limiter = self._get_spend_limiter(task)
        async with limiter.limit('analyze_vuln', **SPEND_LIMITS['analyze_vuln']) as res:
            require(res) # ensure we're allow to spend
            analyze_result = await vuln_analyzer.CRSVuln.from_task(task).analyze_vuln_report(report, model_idx=model_idx)

        match analyze_result:
            case Err() as e:
                logger.error(f"failed to analyze vuln report {data.report_id}!: {e}")
                return e
            case Ok(vuln_analyzer.VulnAnalysis(negative=reason)) if reason is not None:
                logger.info(f"vuln analyzer rejected report {data.report_id}: {reason}")
                # TODO: should we store the reason somewhere?
            case Ok(res):
                assert (vuln := res.positive) is not None, "either negative or positive is non-None"
                logger.info(f"vuln analyzer accepted report {data.report_id}")
                _ = await self.handle_analyzed_vuln(
                    task,
                    VulnSource(report.source),
                    vuln,
                    report_id=data.report_id,
                    sarif_id=report.sarif_id
                )
        return Ok(None)

    @requireable
    async def dedupe_vuln(
        self,
        task: project.Task,
        source: str,
        vuln: AnalyzedVuln,
        report_id: Optional[int] = None,
        sarif_id: Optional[uuid.UUID] = None,
        add_if_new: bool = True
    ) -> Result[tuple[int, bool]]:
        """
        Given an analyzed vuln, dedupe it against the current set of vulns. If it appears to
        be a new vuln and {add_if_new} is True, insert it.

        Returns the vuln id of the corresponding vuln and a bool indicating if the vuln was new.
        """
        vuln_id, new = -1, False
        async with self.dupe_locks[task.task_id]:
            existing_vulns = await self.productsdb.get_vulns_for_task(task.task_id)
            if existing_vulns:
                choice, confidence = require(await triage.dedupe_vulns(
                    task.project.name,
                    vuln,
                    list(existing_vulns.values()),
                ))
                logger.info(f"vuln dedupe {choice=} {confidence=}")
                vuln_id = list(existing_vulns.keys())[choice] if choice >= 0 else choice
            if vuln_id == -1:
                new = True
                if add_if_new:
                    vuln_id = await self.productsdb.add_vuln(
                        task.task_id,
                        task.project.name,
                        vuln,
                        source,
                        report_id=report_id,
                        sarif_id=sarif_id
                    )
                    logger.info(f"created new vuln: {vuln_id=} {source=} {report_id=}")
                    vuln_counter.add(1, {
                        "task": str(task.task_id),
                        "project": task.project.name,
                        "source": source,
                    })
            elif sarif_id is not None:
                await self.productsdb.set_vuln_sarif(vuln_id, sarif_id)
        return Ok((vuln_id, new))

    @requireable
    async def handle_analyzed_vuln(
        self,
        task: project.Task,
        source: VulnSource,
        vuln: AnalyzedVuln,
        report_id: Optional[int] = None,
        sarif_id: Optional[uuid.UUID] = None,
        skip_pov: bool = False
    ) -> Result[int]:
        """
        Dedupes the vuln, potentially creating a new vuln in the DB.
        If the vuln is new, this also submits pov and patch jobs if it is new -
        the pov job submission is skipped if {skip_pov}.

        Returns the vuln_id
        """
        vuln_id, new = require(await self.dedupe_vuln(task, source, vuln, report_id=report_id))
        logger.info(f"vuln deduped -- {source=}, {report_id=}, {vuln_id=}, {new=}")
        submits: list[Coro[None]] = []
        if sarif_id:
            submits.append(
                self.workdb.submit_job(
                    task.task_id,
                    WorkType.BUNDLE_SARIF,
                    SARIFAssessmentData(task_id=task.task_id, vuln_id=vuln_id, sarif_id=sarif_id),
                    expiration=task.deadline_datetime
                )
            )
        if new:
            submits.append(
                self.workdb.submit_job(
                    task.task_id,
                    WorkType.PATCH_VULN,
                    PatchVulnData(vuln_id=vuln_id, pov_ids=None),
                    expiration=task.deadline_datetime,
                )
            )
            if not skip_pov:
                submits.append(self.workdb.submit_job(
                    task.task_id,
                    WorkType.PRODUCE_POV,
                    VulnData(vuln_id=vuln_id),
                    expiration=task.deadline_datetime,
                ))
            logger.info(f"submitting {len(submits)} new jobs for {vuln_id=}")
            _ = await asyncio.gather(*submits)
        return Ok(vuln_id)

    async def cluster_pov(self, task: project.Task, pov_id: int, vuln_id: int, expected: Optional[int]):
        await self.productsdb.assign_vuln_to_pov(pov_id=pov_id, vuln_id=vuln_id)
        submits = [self.workdb.submit_job(
            task.task_id,
            WorkType.BUNDLE_POV,
            POVData(pov_id=pov_id),
            task.deadline_datetime
        )]
        if expected is not None and vuln_id != expected:
            if await self.counterdb.fetch_add(str(task.task_id), f"ExtraProducePov({vuln_id})", 1) < EXTRA_POV_COUNT:
                submits.append(self.workdb.submit_job(
                    task.task_id,
                    WorkType.PRODUCE_POV,
                    VulnData(vuln_id=expected),
                    task.deadline_datetime
                ))
        _ = await asyncio.gather(*submits)

    @telem_tracer.start_as_current_span(
        "crs_task.triage_pov",
        attributes={"crs.action.category": "dynamic_analysis", "crs.action.name": "crs_task.triage_pov"},
        record_exception=False
    )
    @requireable
    async def triage_pov(self, data: TriageData) -> Result[None]:
        logger.info(f"triaging {repr(data)}")
        pov = await self.productsdb.get_pov(data.pov_id)
        if pov is None:
            logger.warning("missing pov in db?")
            return Ok(None)
        task = require(await self.task_from_id(pov.task_uuid))

        # first, check to see if we have bugs which match the full stack trace
        # if so, consider those equivalent and don't triage
        if pov.stack and (vuln_id := await self.productsdb.get_vuln_for_stacktrace(pov.task_uuid, pov.stack)) is not None:
            logger.info(f"assigning {vuln_id=} to {data.pov_id=} based on stacktrace")
            await self.cluster_pov(task, pov_id=data.pov_id, vuln_id=vuln_id, expected=data.expected)
            return Ok(None)

        # if none of that solved our problem, use an LLM to triage the bug
        harnesses = require(await task.project.init_harness_info())
        decoded, _ = await self.decode_pov(task, harnesses, pov)

        limiter = self._get_spend_limiter(task)
        async with limiter.limit("triage_pov", **SPEND_LIMITS["triage_pov"]) as res:
            require(res) # ensure we can spend
            vuln = require(await triage.CRSTriage.from_task(task).pov_triage(decoded))

        vuln_id = require(await self.handle_analyzed_vuln(task, data.source, vuln, skip_pov=True))
        logger.info(f"assigning {vuln_id=} to {data.pov_id=} based on LLM")
        await self.cluster_pov(task, pov_id=data.pov_id, vuln_id=vuln_id, expected=data.expected)
        return Ok(None)

    async def handle_pov_produce_result(self, task: project.Task, vuln_id: int, source: str, with_seed: bool, result: Result[pov_producer.POVProducerResult]):
        match result:
            case Ok(pov_producer.ConfirmedPOVProducerResult() as p):
                pov_id, = await self.productsdb.add_povs([
                    POVRunData(
                        task_uuid=p.target.task_uuid,
                        project_name=p.target.project_name,
                        harness=p.target.harness,
                        sanitizer=p.target.sanitizer,
                        engine=p.target.engine,
                        python=p.pov_python,
                        input=p.crash_result.input,
                        output=p.crash_result.output,
                        dedup=p.crash_result.dedup,
                        stack=p.crash_result.stack
                    )
                ])
                await self.workdb.submit_job(
                    task.task_id,
                    WorkType.TRIAGE_POV,
                    TriageData(pov_id=pov_id, source=VulnSource(source), expected=vuln_id),
                    expiration=task.deadline_datetime,
                    priority=Priority.CRITICAL
                )
                success = True
                pov_counter.add(1, {
                    "task": str(task.task_id),
                    "project": task.project.name,
                    "harness": p.target.harness,
                    "sanitizer": p.target.sanitizer,
                    "success": "1" if success else "0",
                })
            case _ as e:
                pov_counter.add(1, {
                    "task": str(task.task_id),
                    "project": task.project.name,
                    "success": "0",
                })
                extra = 'with seed ' if with_seed else ''
                logger.warning(f"pov producer {extra}failed: {e}")
                return CRSError(f"pov producer {extra}failed: {e}")

    @telem_tracer.start_as_current_span(
        "crs_task.produce_pov",
        attributes={"crs.action.category": "input_generation", "crs.action.name": "crs_task.produce_pov"},
        record_exception=False
    )
    @requireable
    async def produce_pov(self, data: VulnData) -> Result[None]:
        row = await self.productsdb.get_vuln(data.vuln_id)
        if row is None:
            return Err(CRSError(f"vuln_id {data.vuln_id} does not exist"))

        task_id, source, vuln = row
        task = require(await self.task_from_id(task_id))

        def stop_condition(response: Result[pov_producer.POVProducerResult]):
            match response:
                case Ok(pov_producer.ConfirmedPOVProducerResult()):
                    return True
                case _:
                    return False

        crs = self
        params = [
            (harness_input_decoder.PythonHarnessInputDecoder, False),
            (None, False),
            (None, False)
        ]
        if isinstance(task, project.DeltaTask):
            params.extend(
                [
                    (harness_input_decoder.PythonHarnessInputDecoder, True),
                    (None, True),
                    (None, True)
                ]
            )

        def producer(idx: int):
            decoder, rawdiff = params[idx % len(params)]
            class POVProducer(pov_producer.CRSPovProducer):
                async def seed_hook(self, harness_num: int, contents: bytes):
                    await crs.wait_for_bgworker(self.task)
                    _ = await crs.bgworkers[self.task].fuzzer.add_seed_by_num(
                        harness_num=harness_num, contents=contents, never_minimize=True
                    )
                    try:
                        if task.project.harnesses:
                            for i in range(len(task.project.harnesses)):
                                if i == harness_num:
                                    continue
                                _ = await crs.bgworkers[self.task].fuzzer.add_seed_by_num(
                                    harness_num=i, contents=contents, never_minimize=False
                                )
                    except Exception:
                        pass

                async def encoder_hook(self, harness_num: int):
                    return to_tool_result(
                        await crs.get_encoder(
                            task, harness_num, decoder_type=decoder
                        )
                    )

            return POVProducer.from_task(task).produce_pov(vuln, model_idx=idx, rawdiff=rawdiff)

        limiter = self._get_spend_limiter(task)
        async with limiter.limit("produce_pov", **SPEND_LIMITS["produce_pov"]) as res:
            require(res) # ensure we can spend
            coros = [producer(i) for i in range(len(params))]
            errs: list[CRSError] = []
            success = False
            for response in await run_coro_batch(coros, stop_condition=stop_condition, name=f"produce_pov() project={task.project.name}"):
                if err := await self.handle_pov_produce_result(task, data.vuln_id, source, False, response):
                    errs.append(err)
                else:
                    success = True

        if success:
            return Ok(None)
        else:
            # fail after attempt 2? schedule a job to try with a seed if we ever hit the target function
            if await self.counterdb.fetch_add(str(task.task_id), f"ProducePov({data.vuln_id})", 1) == 1:
                await self.workdb.submit_job(
                    task.task_id,
                    WorkType.PRODUCE_POV_HINT,
                    data,
                    expiration=task.deadline_datetime,
                )
            return Err(CRSError(f"pov batch failed - errors:\n{'\n'.join(e.error for e in errs)}"))


    @telem_tracer.start_as_current_span(
        "crs_task.produce_pov",
        attributes={"crs.action.category": "input_generation", "crs.action.name": "crs_task.produce_pov"}
    )
    @requireable
    async def produce_pov_if_hit(self, data: VulnData) -> Result[None]:
        row = await self.productsdb.get_vuln(data.vuln_id)
        if row is None:
            return Err(CRSError(f"vuln_id {data.vuln_id} does not exist"))

        task_id, source, vuln = row
        task = require(await self.task_from_id(task_id))
        _ = await task.coverage.init()

        if await self.productsdb.get_submittable_pov_ids_for_vuln(data.vuln_id):
            # already handled
            return Ok(None)

        # get the locations to hit
        defns = require(await task.project.searcher.find_definition(vuln.function, vuln.file))
        if len(defns) > 1:
            return Err(CRSError(f"got extra files from find definition with path"))

        tree = (await task.project.vfs.tree()).unwrap_or(None)
        if tree:
            file = (tree.normalize_path(defns[0].file_name)).unwrap_or(defns[0].file_name)
        else:
            file = defns[0].file_name
        def is_hit():
            for defn in defns[0].defs:
                if task.coverage.query_hit(file, defn.line):
                    return True
            return False

        # wait until we think we hit the function
        async with task.coverage.new_coverage:
            _ = await task.coverage.new_coverage.wait_for(is_hit)

        if await self.productsdb.get_submittable_pov_ids_for_vuln(data.vuln_id):
            # already handled while we waited
            return Ok(None)

        # get the seed that reaches
        for defn in defns[0].defs:
            match task.coverage.graph.get_info_for_line(file, defn.line):
                case None:
                    pass
                case _, node:
                    if node.closest is not None:
                        if node.closest.distance == 0:
                            # direct hit, no one else will be closer
                            break
        else:
            return Err(CRSError(f"our matching line went away"))

        contents = require(await task.coverage.db.get_input(node.closest.input_id))

        # decode the input
        harnesses = require(await task.project.init_harness_info())
        dummy_pov = POVRunData(
            task_uuid=task_id,
            project_name=task.project.name,
            harness=harnesses[node.closest.harness].name,
            sanitizer="",
            engine="",
            python=None,
            input=contents,
            output="",
            dedup="",
            stack="",
        )
        decoded, decoder = await self.decode_pov(task, harnesses, dummy_pov, try_keep_raw=True)

        crs = self
        class POVProducer(pov_producer.CRSPovProducer):
            async def seed_hook(self, harness_num: int, contents: bytes):
                await crs.wait_for_bgworker(self.task)
                _ = await crs.bgworkers[self.task].fuzzer.add_seed_by_num(
                    harness_num=harness_num, contents=contents, never_minimize=True
                )
            async def encoder_hook(self, harness_num: int):
                return to_tool_result(
                    await crs.get_encoder(
                        task, harness_num, decoder_type= type(decoder) if decoder is not None else None
                    )
                )
        close_pov = (
            decoded,
            vuln.file,
            vuln.function,
        )

        limiter = self._get_spend_limiter(task)
        async with limiter.limit("produce_pov", **SPEND_LIMITS["produce_pov"]) as res:
            require(res) # ensure we can spend
            pov_res = await POVProducer.from_task(task).produce_pov(vuln, model_idx=0, close_pov=close_pov)

        if err := await self.handle_pov_produce_result(task, data.vuln_id, source, True, pov_res):
            return Err(err)
        return Ok(None)

    async def schedule_new_patcher(self, task: project.Task, vuln_id: int, patched_povs: list[int], unpatched_povs: list[int]):
        # mix-in one of the patched povs (if it exists) near the beginning (so it is displayed to the agent)
        pov_ids = patched_povs[:1] + unpatched_povs
        await self.workdb.submit_job(
            task.task_id,
            WorkType.PATCH_VULN,
            PatchVulnData(vuln_id=vuln_id, pov_ids=pov_ids),
            task.deadline_datetime
        )

    async def maybe_update_bundle(self, task: project.Task, vuln_id: int, sarif_id: Optional[uuid.UUID] = None)-> bool:
        bundle = await self.productsdb.get_or_create_bundle(task.task_id, vuln_id)
        original = (bundle.patch_id, bundle.pov_id, bundle.sarif_id)

        # first check if we need to invalidate any failed submissions
        (patch_submission, pov_submission, _, _) = await self.productsdb.get_bundle_submissions(bundle.id)
        if patch_submission and patch_submission.status == 'failed':
            bundle.patch_id = None
            await self.counterdb.add(str(task.task_id), "bundled_failed_patches", 1)
        if pov_submission and pov_submission.status == 'failed':
            bundle.pov_id = None

        # next check if we have errored submissions to re-submit
        resubmit = False
        if patch_submission and patch_submission.status == 'errored' and bundle.patch_id is not None:
            resubmit = True
            await self.productsdb.clear_patch_submission(bundle.patch_id)
        if pov_submission and pov_submission.status == 'errored' and bundle.pov_id is not None:
            resubmit = True
            await self.productsdb.clear_pov_submission(bundle.pov_id)

        # check for a patch which covers all POVs for the vuln
        vuln_results = await self.productsdb.get_patch_results(task.task_id, vuln_id=vuln_id)
        good_patches = set(await self.productsdb.get_submittable_patch_ids_for_vuln(vuln_id))
        failed_povs: set[int] = set()
        for patch_id, pov_id, patched in vuln_results:
            if patched:
                continue
            good_patches.discard(patch_id)
            failed_povs.add(pov_id)

        # confirm or assign a new patch_id; if none are good, schedule a new patcher
        if bundle.patch_id is not None and bundle.patch_id in good_patches:
            logger.info(f"bundle {(task.task_id, vuln_id)} already has a good patch")
        elif len(good_patches) > 0:
            bundle.patch_id = good_patches.pop()
            logger.info(f"setting bundle {(task.task_id, vuln_id)} patch to {bundle.patch_id}")
        elif bundle.patch_id is not None:
            logger.info(f"unsetting patch_id for bundle {(task.task_id, vuln_id)}")
            bundle.patch_id = None
            await self.schedule_new_patcher(task, vuln_id, [], list(failed_povs))

        # assign a pov id if needed and possible
        good_povs = await self.productsdb.get_submittable_pov_ids_for_vuln(vuln_id)
        if bundle.pov_id is None and len(good_povs) > 0:
            bundle.pov_id = good_povs[0]

        # assign a sarif_id if needed and possible
        # NOTE: we assume at most 1 sarif per vuln_id
        if bundle.sarif_id is None and sarif_id is not None:
            bundle.sarif_id = sarif_id

        # if anything changed, update the bundle in the DB and spawn a submitter job
        if (bundle.patch_id, bundle.pov_id, bundle.sarif_id) != original:
            logger.info(f"bundle {bundle.id} changed, updating it in DB and submitting")
            if bundle.patch_id is not None and bundle.pov_id is not None:
                # submitting a tested patch
                await self.counterdb.add(str(task.task_id), "bundled_tested_patches", 1)
            elif bundle.patch_id is not None:
                # submitting an untested patch
                await self.counterdb.add(str(task.task_id), "bundled_untested_patches", 1)

            await self.productsdb.update_bundle(bundle)
            await self.workdb.submit_job(
                task.task_id,
                WorkType.SUBMIT_BUNDLE,
                BundleData(task_id=task.task_id, vuln_id=vuln_id),
                task.deadline_datetime
            )
            # did update bundle
            return True
        # we aren't changing data to submit, we're merely re-queuing now that we've wiped the pov/patch submission
        # due to a server-side error
        elif resubmit:
            await self.workdb.submit_job(
                task.task_id,
                WorkType.SUBMIT_BUNDLE,
                BundleData(task_id=task.task_id, vuln_id=vuln_id),
                task.deadline_datetime
            )
            # did update bundle
            return True

        return False

    @requireable
    async def bundle_pov(self, data: POVData) -> Result[None]:
        pov = await self.productsdb.get_pov(data.pov_id)
        if pov is None:
            return Err(CRSError(f"pov {data.pov_id} does not exist"))
        if pov.vuln_id is None:
            return Err(CRSError(f"pov {data.pov_id} does not have a vuln_id assigned"))
        task = require(await self.task_from_id(pov.task_uuid))

        async with self.bundle_conds[task.task_id]:
            patches = await self.productsdb.get_patches_for_task(task.task_id)
            results = require(await test_povs_on_patches(task, [(patch, [pov]) for patch in patches.values()]))

            # store patch results in DB
            logger.info(f"pov patch results: {data.pov_id=} {results=}")
            await self.productsdb.add_patch_results(
                task.task_id,
                [(patch_id, data.pov_id, res) for patch_id, [res] in zip(patches.keys(), results)]
            )

            if await self.maybe_update_bundle(task, pov.vuln_id):
                self.bundle_conds[task.task_id].notify_all()

        return Ok(None)

    @requireable
    async def bundle_patch_no_pov(self, data: DelayPatchData) -> Result[None]:
        patch = await self.productsdb.get_patch(data.patch_id)
        if patch is None:
            return Err(CRSError(f"patch {data.patch_id} does not exist"))
        task = require(await self.task_from_id(patch.task_uuid))

        # wait until deadline (or a little before the task expires)
        deadline = min(data.deadline, task.deadline_datetime - timedelta(minutes=30))
        duration = (deadline - datetime.now(timezone.utc)).total_seconds()

        async with self.bundle_conds[task.task_id]:
            async def wait_for_povs():
                if await self.productsdb.get_povs_for_vuln(patch.vuln_id):
                    return
                while True:
                    _ = await self.bundle_conds[task.task_id].wait()
                    if await self.productsdb.get_povs_for_vuln(patch.vuln_id):
                        return
            try:
                await asyncio.wait_for(wait_for_povs(), duration)
            except TimeoutError:
                pass

        await self.workdb.submit_job(
            task.task_id,
            WorkType.BUNDLE_PATCH,
            PatchData(patch_id=data.patch_id, pov_verified=False),
            task.deadline_datetime
        )

        return Ok(None)

    @requireable
    async def bundle_patch(self, data: PatchData) -> Result[None]:
        patch = await self.productsdb.get_patch(data.patch_id)
        if patch is None:
            return Err(CRSError(f"patch {data.patch_id} does not exist"))
        task = require(await self.task_from_id(patch.task_uuid))

        async with self.bundle_conds[task.task_id]:
            # consider this "bundled" once we productsdb.add_patch_results
            # should we bundle this? depends on our patch status
            if not isinstance(task, project.DeltaTask) and not data.pov_verified:
                matching_povs = await self.productsdb.get_povs_for_vuln(patch.vuln_id)
                while len(matching_povs) == 0: # if we get a pov, then this will become a tested patch!
                    tested = await self.counterdb.get(str(task.task_id), "bundled_tested_patches")
                    untested = await self.counterdb.get(str(task.task_id), "bundled_untested_patches")
                    failed = await self.counterdb.get(str(task.task_id), "bundled_failed_patches")
                    if (tested - failed) * UNVERIFIED_PATCH_RATIO > untested:
                        break

                    # wait until we have more tested patches or povs
                    _ = await self.bundle_conds[task.task_id].wait()
                    matching_povs = await self.productsdb.get_povs_for_vuln(patch.vuln_id)

            povs = await self.productsdb.get_povs_for_task(task.task_id)
            pov_results, = require(await test_povs_on_patches(task, [(patch, list(povs.values()))]))

            # store patch results in DB
            logger.info(f"patch results: {data.patch_id=} {pov_results=}")
            await self.productsdb.add_patch_results(
                task.task_id,
                [(data.patch_id, pov_id, res) for pov_id, res in zip(povs.keys(), pov_results)]
            )

            # find any povs with this vuln_id that are unpatched by the new patch
            unpatched_povs: list[int] = []
            patched_povs: list[int] = []
            for (pov_id, pov), res in zip(povs.items(), pov_results):
                if pov.vuln_id != patch.vuln_id:
                    continue
                if res:
                    patched_povs.append(pov_id)
                else:
                    unpatched_povs.append(pov_id)
            if unpatched_povs:
                logger.info(f"patch {data.patch_id=} failed on {unpatched_povs=}, scheduling new patcher")
                await self.schedule_new_patcher(task, patch.vuln_id, patched_povs, unpatched_povs)
            else:
                if await self.maybe_update_bundle(task, patch.vuln_id):
                    self.bundle_conds[task.task_id].notify_all()

        return Ok(None)

    @requireable
    async def bundle_sarif(self, data: SARIFAssessmentData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))
        async with self.bundle_conds[task.task_id]:
            _ = await self.maybe_update_bundle(task, data.vuln_id, sarif_id=data.sarif_id)
        return Ok(None)

    @telem_tracer.start_as_current_span(
        "submitter",
        attributes={"crs.action.category": "scoring_submission"},
        record_exception=False
    )
    @requireable
    async def submit_bundle(self, data: BundleData) -> Result[None]:
        task = require(await self.task_from_id(data.task_id))

        while not await self.submitter.ping():
            logger.warning("cannot ping competition API, retrying soon")
            await asyncio.sleep(PING_FAIL_DELAY)

        polling = False
        async with asyncio.TaskGroup() as tg:
            async with self.bundle_conds[task.task_id]:
                bundle = await self.productsdb.get_or_create_bundle(task.task_id, data.vuln_id)
                (
                    patch_submission,
                    pov_submission,
                    sarif_submission,
                    bundle_submission
                ) = await self.productsdb.get_bundle_submissions(bundle.id)

                row = await self.productsdb.get_vuln(bundle.vuln_id)
                assert row is not None
                _, _, vuln = row

                if bundle.patch_id is not None and patch_submission is None:
                    # our bundling logic is responsible for limiting what is available
                    # so if we see it, then it is ready to submit
                    patch = await self.productsdb.get_patch(bundle.patch_id)
                    assert patch is not None
                    patch_submission = await self.submitter.submit_patch(task.task_id, bundle.patch_id, patch)
                    submission_counter.add(1, {
                        "task": str(task.task_id),
                        "project": task.project.name,
                        "type": "patch",
                    })

                if patch_submission and patch_submission.status == 'accepted':
                    assert bundle.patch_id is not None
                    polling = True
                    _ = tg.create_task(
                        self.submitter.poll_patch(task.task_id, bundle.patch_id, patch_submission),
                        name=f"poll_patch({bundle.patch_id}, {patch_submission.id()}"
                    )

                if bundle.pov_id is not None and pov_submission is None:
                    pov = await self.productsdb.get_pov(bundle.pov_id)
                    assert pov is not None
                    pov_submission = await self.submitter.submit_pov(task.task_id, bundle.pov_id, pov)
                    submission_counter.add(1, {
                        "task": str(task.task_id),
                        "project": task.project.name,
                        "type": "pov",
                    })

                if pov_submission and pov_submission.status == 'accepted':
                    assert bundle.pov_id is not None
                    polling = True
                    _ = tg.create_task(
                        self.submitter.poll_pov(task.task_id, bundle.pov_id, pov_submission),
                        name=f"poll_pov({bundle.pov_id}, {pov_submission.id()}"
                    )

                if bundle.sarif_id is not None and sarif_submission is None:
                    sarif_submission = await self.submitter.submit_sarif_assessment(task.task_id, bundle.vuln_id, bundle.sarif_id, True, vuln.description)
                    submission_counter.add(1, {
                        "task": str(task.task_id),
                        "project": task.project.name,
                        "type": "sarif",
                    })

                should_submit_bundle = [patch_submission, pov_submission, sarif_submission].count(None) < 2
                if should_submit_bundle and bundle_submission is None:
                    response = await self.submitter.submit_bundle(
                        task.task_id,
                        bundle.id,
                        vuln.description,
                        patch_submission.id() if patch_submission else None,
                        pov_submission.id() if pov_submission else None,
                        sarif_submission.id() if sarif_submission else None,
                        None
                    )
                    bundle_submission = response.id()
                    submission_counter.add(1, {
                        "task": str(task.task_id),
                        "project": task.project.name,
                        "type": "bundle",
                    })
                elif should_submit_bundle and bundle_submission is not None:
                    response = await self.submitter.update_bundle(
                        task.task_id,
                        bundle.id,
                        bundle_submission.id(),
                        vuln.description,
                        patch_submission.id() if patch_submission else None,
                        pov_submission.id() if pov_submission else None,
                        sarif_submission.id() if sarif_submission else None,
                        None
                    )
                elif not should_submit_bundle and bundle_submission is not None:
                    await self.submitter.delete_bundle(task.task_id, bundle.id, bundle_submission.id())

        # if we were polling, reacquire the lock and update the bundle if needed
        if polling:
            async with self.bundle_conds[data.task_id]:
                _ = await self.maybe_update_bundle(task, data.vuln_id)

        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.pre_flip_branch",
        attributes={"crs.action.name": "crs_task.pre_flip_branch"},
        record_exception=False
    )
    @requireable
    async def pre_flip_branch(self, frontier_data: PreBranchFlipData) -> Result[None]:
        elapsed = (datetime.now(timezone.utc) - frontier_data.submission_time).total_seconds()
        task = require(await self.task_from_id(frontier_data.task_id))

        if await self.counterdb.get(str(frontier_data.task_id), "FLIP_BRANCH") > MAX_BRANCH_FLIP_PER_TASK:
            return Err(CRSError("exceeded branch flip budget for task"))

        await self.wait_for_bgworker(task)
        coverage_analyzer = self.bgworkers[task].coverage.cov
        match await branch_flipper.pre_flip_branch(
            project=task.project, cov=coverage_analyzer, frontier=frontier_data.frontier, age=elapsed
        ):
            case Ok(True):
                await self.workdb.submit_job(
                    task.task_id,
                    WorkType.FLIP_BRANCH,
                    BranchFlipData(task_id=frontier_data.task_id, frontier=frontier_data.frontier),
                    expiration=task.deadline_datetime,
                    priority=(1 - 1 / max(1, frontier_data.frontier.score)) * Priority.LOW,
                )
            case Ok(_):
                pass
            case Err() as e:
                logger.error("preflip err: {e}", e=e)
                pass
        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.pre_flip_branch",
        attributes={"crs.action.name": "crs_task.pre_flip_branch"},
        record_exception=False
    )
    @requireable
    async def flip_branch(self, frontier_data: BranchFlipData) -> Result[None]:
        task = require(await self.task_from_id(frontier_data.task_id))

        # count how many branch flips in RUNNING, DONE, FAILED state for this task
        # if it above our threshold, then don't run any more jobs
        if await self.counterdb.get(str(frontier_data.task_id), "FLIP_BRANCH") > MAX_BRANCH_FLIP_PER_TASK:
            return Err(CRSError("exceeded branch flip budget for task"))
        elif await self.counterdb.fetch_add(str(frontier_data.task_id), "FLIP_BRANCH", 1) > MAX_BRANCH_FLIP_PER_TASK:
            return Err(CRSError("exceeded branch flip budget for task"))

        frontier = frontier_data.frontier
        target_file, _, _, target_func = frontier.target.split(":", maxsplit=3)
        reached_file, _, _, reached_func = frontier.closest.split(":", maxsplit=3)

        # get inputs
        await self.wait_for_bgworker(task)
        coverage_analyzer = self.bgworkers[task].coverage.cov
        contents = require(await coverage_analyzer.db.get_input(frontier.input_id))

        # decode the input
        harnesses = require(await task.project.init_harness_info())
        dummy_pov = POVRunData(
            task_uuid=frontier_data.task_id,
            project_name=task.project.name,
            harness=harnesses[frontier.harness_num].name,
            sanitizer="",
            engine="",
            python=None,
            input=contents,
            output="",
            dedup="",
            stack="",
        )
        decoded, decoder = await self.decode_pov(task, harnesses, dummy_pov, try_keep_raw=True)
        # fetch corresponding encoder
        encoder = require(
            await self.get_encoder(task, frontier.harness_num, type(decoder) if decoder is not None else None)
        )

        # run branch flipper
        result = require(await branch_flipper.CRSBranchFlipper.from_task(task).try_reach_raw(
            decoded,
            encoder,
            frontier.harness_num,
            target_file,
            target_func,
            reached_file,
            reached_func,
        ))
        err = None
        if isinstance(result, branch_flipper.ConfirmedBranchFlipperResult):
            logger.info("branchflip {target_file}:{target_func} confirmed success!", target_file=target_file, target_func=target_func)
        elif result.reach_target_function:
            logger.info("branchflip {target_file}:{target_func} unconfirmed success", target_file=target_file, target_func=target_func)
        else:
            logger.info("branchflip {target_file}:{target_func} likely failure", target_file=target_file, target_func=target_func)
            err = Err(CRSError("branch flipper failure: self reported"))

        branch_flip_counter.add(1, {
            "task": str(frontier_data.task_id),
            "project": task.project.name,
            "success": "1" if err is None else "0",
        })

        if not result.input_python:
            return Err(CRSError("branch flipper failure: no python"))
        match await task.project.build_pov(result.input_python):
            # even if it wasn't verified, we can try adding the seed.
            # Sometimes the verification is wrong, so it's worth just using it.
            # We leave never_minimize as false: if it was useful, the minset will keep it
            case Ok(contents):
                _ = await self.bgworkers[task].fuzzer.add_seed_by_num(
                    harness_num=frontier.harness_num, contents=contents, never_minimize=False
                )
                # we can add the seed, but report error based on what we believe so our db stats are more useful
                return err or Ok(None)
            case _:
                return Err(CRSError("branch flipper failure: python run failure"))

    @telem_tracer.start_as_current_span(
        "crs_task.launch_builds",
        attributes={"crs.action.category": "building", "crs.action.name": "crs_task.launch_builds"},
        record_exception=False
    )
    @requireable
    async def launch_builds(self, task_data: TaskData) -> Result[None]:
        logger.info(f"launching task {task_data=}")
        task_id = task_data.task_id
        task = require(await self.task_from_id(task_id))
        project_name = task.project.name

        async with ExceptAndLogTaskGroup() as tg:
            # kickoff bear build first so it gets priority on the build lock
            _ = tg.create_task(task.project.build_bear_tar(), name=f"build_bear_tar() project={project_name} {task_id=}")

            # kickoff main build and init harness info
            harness_info_task = tg.create_task(task.project.init_harness_info(), name=f"init_harness_info() project={project_name} {task_id=}")

            if isinstance(task, project.DeltaTask):
                # kickoff main build and init harness info for base project
                _ = tg.create_task(task.base.init_harness_info(), name=f"init_harness_info() (delta base) project={project_name} {task_id=}")

            # kickoff debug build
            _ = tg.create_task(debugger.Debugger(task.project).artifacts(), name=f"debug_build project={project_name} {task_id=}")

            # kickoff coverage build
            _ = tg.create_task(coverage.CoverageAnalyzer(task.project).artifacts(), name=f"coverage_build project={project_name} {task_id=}")

            match await harness_info_task:
                case None | Err(_):
                    logger.warning(f"no harness info found for task {task_data.task_id}")
                case Ok(harnesses):
                    if len(harnesses) > MAX_HARNESS_PRECOMPUTE:
                        logger.warning(f"too many harnesses to precompute them all: {len(harnesses)}")
                        harnesses = harnesses[:MAX_HARNESS_PRECOMPUTE]
                    _ = await asyncio.gather(*(self.workdb.submit_job(
                        task_data.task_id,
                        WorkType.ANALYZE_HARNESS,
                        HarnessData(task_id=task_data.task_id, harness_num=harness_num),
                        task.deadline_datetime,
                        unique=True,
                    ) for harness_num in range(len(harnesses))))

        return Ok(None)

    @telem_tracer.start_as_current_span(
        "crs_task.launch_task",
        attributes={"crs.action.name": "crs_task.launch_task"},
        record_exception=False
    )
    @requireable
    async def launch_task(self, task_data: TaskDataHarnesses) -> Result[None]:
        logger.info(f"launching task {task_data=}")
        task = require(await self.task_from_id(task_data.task_id))

        if not task_data.harnesses_included:
            logger.warning(f"skipping task {task.task_id}:{task.project.name} it has no harnesses")
            return Ok(None)

        submit_coros: list[Awaitable[None]] = []

        submit_coros.append(self.workdb.submit_job(
            task.task_id,
            WorkType.LAUNCH_TASK_SCOPE,
            TaskData(task_id=task.task_id),
            expiration=task.deadline_datetime,
            unique=True,
        ))

        # immediately launch builds
        submit_coros.append(self.workdb.submit_job(
            task.task_id,
            WorkType.LAUNCH_BUILDS,
            TaskData(task_id=task.task_id),
            expiration=task.deadline_datetime,
            unique=True,
        ))

        if isinstance(task, project.DeltaTask):
            submit_coros.append(self.workdb.submit_job(
                task.task_id,
                WorkType.ANALYZE_DIFF,
                TaskData(task_id=task.task_id),
                expiration=task.deadline_datetime,
            ))
        else:
            match task.project.info.language:
                case "c"|"c++":
                    submit_coros.append(self.workdb.submit_job(
                        task.task_id,
                        WorkType.LAUNCH_INFER,
                        TaskData(task_id=task.task_id),
                        expiration=task.deadline_datetime,
                        unique=True,
                    ))
                case _:
                    logger.warning(f"infer not supported for language {task.project.info.language} yet")

            for multi in (False, True):
                submit_coros.append(self.workdb.submit_job(
                    task.task_id,
                    WorkType.LAUNCH_AINALYSIS_M if multi else WorkType.LAUNCH_AINALYSIS,
                    TaskData(task_id=task.task_id),
                    expiration=task.deadline_datetime,
                    unique=True,
                ))

        submit_coros.append(self.workdb.submit_job(
            task.task_id,
            WorkType.LAUNCH_BGWORKERS,
            TaskData(task_id=task.task_id),
            expiration=task.deadline_datetime,
            unique=True,
        ))
        _ = await asyncio.gather(*submit_coros)
        return Ok(None)


    async def loop(self):
        logger.info("Starting main CRS loop...")
        _ = running_crs.set(self)
        # handle new tasks, submit things, etc
        async with contextlib.AsyncExitStack() as stack:
            tg = await stack.enter_async_context(asyncio.TaskGroup())
            _ = await stack.enter_async_context(self.workdb.sqlite_exclusive())
            _ = await stack.enter_async_context(self.taskdb.sqlite_pin())
            _ = await stack.enter_async_context(self.productsdb.sqlite_pin())
            _ = await stack.enter_async_context(self.counterdb.sqlite_pin())

            _ = tg.create_task(async_latency_monitor(), name="async_latency_monitor()")
            _ = tg.create_task(self.workdb.loop(), name="workdb.loop()")

            last_task_id, last_cancelled_id, last_sarif_id = -1, -1, -1
            while True:
                last_task_id, db_tasks = await self.taskdb.get_tasks(after=last_task_id)
                _ = await asyncio.gather(*(self.workdb.submit_job(
                    db_task.task_id,
                    WorkType.LAUNCH_TASK,
                    TaskDataHarnesses(task_id=db_task.task_id, harnesses_included=db_task.harnesses_included),
                    datetime.fromtimestamp(db_task.deadline / 1000, tz=timezone.utc),
                    unique=True,
                ) for db_task in db_tasks))

                last_sarif_id, db_sarifs = await self.taskdb.get_sarifs(after=last_sarif_id)
                _ = await asyncio.gather(*(self.workdb.submit_job(
                    db_sarif.task_id,
                    WorkType.LAUNCH_SARIF,
                    SARIFData(
                        task_id=db_sarif.task_id,
                        sarif_id=db_sarif.sarif_id,
                        sarif=db_sarif.sarif
                    ),
                    expiration=datetime.now(timezone.utc) + timedelta(days=1), # we don't have the task deadline handy
                    unique=True,
                ) for db_sarif in db_sarifs))

                last_cancelled_id, cancelled_ids = await self.taskdb.get_cancelled(after=last_cancelled_id)
                for cancelled_id in cancelled_ids:
                    await self.workdb.cancel_tasks(cancelled_id)

                await asyncio.sleep(TASKDB_POLL_PERIOD)
