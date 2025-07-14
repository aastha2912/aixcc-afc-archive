from asyncio.subprocess import DEVNULL, PIPE, STDOUT
import asyncio
import contextlib
import math
import os
import re
import shutil
import tarfile
import time

from collections import Counter, defaultdict
from enum import Enum, auto
from hashlib import sha1
from crs.common.aio import Path, batch_unlink
from typing import Any, AsyncIterator, Awaitable, Callable, Collection, Optional, Iterable

from opentelemetry import trace

from crs.common.constants import SANITIZER_VARS
from crs.config import telem_tracer, metrics, CACHE_DIR, CORPUS_SAMPLE, CRS_BLOB_ENDPOINT, CRS_DEDUP_MON
from crs.common.alru import async_once, alru_cache
from crs.common.types import CRSError, Result, Ok, Err, POVTarget
from crs.common.utils import finalize, require, requireable, scoped_pipe, only_ok
from crs.modules.project import BuildArtifacts, BuildConfig, CrashResult, Harness, Project, Task, DEDUPE_FRAMES_C, DEDUPE_FRAMES_JAVA
from crs.common import docker

from crs_rust import logger
import crs_rust

SINGLE_FUZZER_TIMEOUT=180
FUZZER_GRACE_PERIOD=30
MINIMIZE_TIMEOUT=600
CORPUS_MATCH_TIMEOUT=1800
CORPUS_MATCH_MAX=30
CORPUS_MATCH_SLOW=300
CORPUS_MATCH_SLOW_MAX=4
MAX_CRASHES_PER_BUCKET=20
MAX_SECONDARY_FUZZ_JOBS=16
REBALANCE_COOLDOWN=1

CORPUS_MATCH_SEM = asyncio.Lock()

seed_gauge = metrics.create_gauge("fuzz_seed")
seed_counter = metrics.create_counter("fuzz_seed_counter")
seed_callbacks_counter = metrics.create_counter("fuzz_seed_callbacks")
crash_gauge = metrics.create_gauge("fuzz_crash")
crash_counter = metrics.create_counter("fuzz_crash_counter")
crash_callbacks_counter = metrics.create_counter("fuzz_crash_callbacks")
fuzz_time_counter = metrics.create_counter("fuzz_time")

@contextlib.asynccontextmanager
async def time_counter_block(counter: crs_rust.Counter, attributes: dict[str, Any]) -> AsyncIterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        counter.add(elapsed, attributes)

class FuzzType(Enum):
    Merge = auto()
    C = auto()
    JVM = auto()

@contextlib.asynccontextmanager
async def invoke(
    run: docker.DockerRun,
    harness: str,
    libfuzzer_args: dict[str, Any],
    fuzzing: FuzzType,
    *args: str,
    **env: str,
) -> AsyncIterator[asyncio.subprocess.Process]:
    env['RUN_FUZZER_MODE'] = "''"
    env['SKIP_SEED_CORPUS'] = "1"
    env['JAVA_OPTS'] = '-XX:ActiveProcessorCount=2'
    if fuzzing != FuzzType.Merge:
        for san in SANITIZER_VARS:
            env[san] = f'"${san}:dedup_token_length={DEDUPE_FRAMES_C*2 if fuzzing == FuzzType.C else DEDUPE_FRAMES_JAVA*2}"'
    inner_cmd = (
        f"{' '.join(f'{k}={v}' for k,v in env.items())} "
        f"run_fuzzer {harness} "
        f"{' '.join(f'-{k}={v}' for k,v in libfuzzer_args.items())} "
        f"{' '.join(args)}"
    )
    async with run.exec_scoped("bash", "-c", inner_cmd, stdout=PIPE, stderr=PIPE) as proc:
        yield proc

@async_once
async def get_seed_map() -> dict[str, tuple[str, str]]:
    r = await asyncio.to_thread(lambda : tarfile.open(CORPUS_SAMPLE, "r:xz").getnames())
    res: dict[str, tuple[str, str]] = {}
    for path in r:
        if "__" not in path:
            continue
        collection, kind, hash = os.path.basename(path).split("__")
        res[hash] = (collection, kind)
    return res

class CorpusManager:
    def __init__(self, project: Project, harness: Harness, build_config: BuildConfig, debug_name: str = ""):
        self.project = project
        self.harness = harness

        self.minimizing_lock = asyncio.Lock()

        # TODO: do we need any special locking around these?
        self.seed_path = project.data_dir / f"seeds_{harness.name}_{build_config.FUZZING_ENGINE}"
        self.crash_path = project.data_dir / f"crashes_{harness.name}_{build_config.FUZZING_ENGINE}"
        self.untested_crash_path = self.crash_path / "untested"
        self.seeds: set[str] = set()
        self.crash_buckets: dict[str, list[str]] = {}
        self.crashes: set[str] = set()
        self.last_min_size = 0

        self.telem_attrs: dict[str, str] = {
            "project": project.name,
            "harness": harness.name,
            "sanitizer": build_config.SANITIZER,
        }

    async def init(self) -> None:
        await self.seed_path.mkdir(exist_ok=True)
        await self.crash_path.mkdir(exist_ok=True)
        await self.untested_crash_path.mkdir(exist_ok=True)
        # re-load crashes and seeds in case we had some already in the folder
        async with self.crash_path.iterdir() as bucket_it:
            async for bucket in bucket_it:
                async with bucket.iterdir() as crash_it:
                    async for crash in crash_it:
                        self.crash_buckets[bucket.name] = self.crash_buckets.get(bucket.name, [])
                        self.crash_buckets[bucket.name].append(crash.name)
                        self.crashes.add(crash.name)
        async with self.seed_path.iterdir() as seed_it:
            async for seed in seed_it:
                self.seeds.add(seed.name)
        try:
            self.last_min_size = int(await self.seed_path.with_suffix(".checkpoint").read_text())
        except OSError:
            self.last_min_size = len(self.seeds)

        seed_gauge.set(len(self.seeds), self.telem_attrs)
        crash_gauge.set(len(self.crashes), self.telem_attrs)

    @property
    def target_seed_path(self):
        return Path("/tmp/") / self.seed_path.name

    @property
    def target_crash_path(self):
        return Path("/tmp/") / self.crash_path.name

    def should_minimize(self) -> bool:
        # do a new minset when we double our corupus size (once we've hit at least 100 seeds)
        return len(self.seeds) > max(100, self.last_min_size*2)

    # we must take in a collection of files to include to include to help alleviate races
    # where a file is modified as we are running
    async def untar_to_docker(self, run: docker.DockerRun, include: Collection[str]) -> Result[None]:
        logger.debug("untar to docker start")
        if len(include) == 0:
            return Ok(None)

        async with contextlib.AsyncExitStack() as stack:
            with scoped_pipe() as (pipe_read, pipe_write):
                tar = await stack.enter_async_context(run.scope.exec_scoped(
                    "tar", "-czf", "-", "--null", "--verbatim-files-from", "--ignore-failed-read",
                    "-C", self.seed_path.parent.as_posix(), f"--files-from=/dev/stdin",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=pipe_write,
                    stderr=asyncio.subprocess.PIPE,
                ))

                # we have --ignore-failed-read here because it is possible for a minset to run concurrently with
                # copying files to a fuzzing docker. If a file is missing due to this, THAT IS FINE
                proc = await stack.enter_async_context(run.exec_scoped(
                    "tar", "xzf", "-", "-C", self.target_seed_path.parent.as_posix(),
                    stdin=pipe_read, stdout=PIPE, stderr=PIPE,
                ))

            prefix = self.seed_path.name

            gather = asyncio.gather(
                tar.communicate(("\0".join([f"{prefix}/{f}" for f in include])).encode()),
                proc.communicate(),
            )
            try:
                (_, tar_stderr), (proc_stdout, proc_stderr) = await gather
            except Exception:
                _ = gather.cancel()
                raise

            if tar.returncode != 0 or proc.returncode != 0:
                return Err(CRSError(f"error transferring seed tarball: tar:{tar.returncode}) {tar_stderr!r}; proc: {proc.returncode} {proc_stdout!r} {proc_stderr!r}"))
            return Ok(None)

    async def grab_crashes(self, run: docker.DockerRun) -> dict[str, bytes]:
        crashes: dict[str, bytes] = {}
        crash_paths = await docker.vls(run, self.target_crash_path.as_posix())
        match await docker.vread_many(
            run,
            [(self.target_crash_path / crash).as_posix() for crash in crash_paths],
        ):
            case Err() as e:
                logger.error(f"serious error occured when trying to read crashes: {e}")
            case Ok(crash_files):
                crashes = {os.path.basename(name):data for name, data in crash_files.items()}
        return crashes

    @telem_tracer.start_as_current_span("corpus_match", record_exception=False)
    @requireable
    async def match_corpus(self, artifacts: BuildArtifacts) -> Result[tuple[list[str], dict[str, bytes]]]:
        try:
            async with (
                CORPUS_MATCH_SEM,
                self.minimizing_lock,
                artifacts.run(
                    timeout=CORPUS_MATCH_TIMEOUT,
                    group=docker.DockerGroup.Build,
                    mounts={Path("/usr/bin/azcopy"):"/usr/bin/azcopy"}
                ) as run
            ):
                start = time.perf_counter()
                logger.info(f"starting corpus match on {self.project.name}/{self.harness.name}")
                # copy in our samples from blob storage
                async def azcopy(url: str, dst: str):
                    docker_args = None
                    if login := os.getenv("AZCOPY_AUTO_LOGIN_TYPE"):
                        docker_args = ["-e", f"AZCOPY_AUTO_LOGIN_TYPE={login}"]

                    async with run.exec_scoped(
                        "azcopy", "copy", "--log-level=NONE", url, dst,
                        docker_args=docker_args, stdout=DEVNULL, stderr=DEVNULL
                    ) as proc:
                        _ = await proc.communicate()
                        if proc.returncode != 0:
                            return Err(CRSError(f"could not download {url} to {dst}"))
                    return Ok(None)

                require(await azcopy(f"{CRS_BLOB_ENDPOINT}/crs/sample.tar.xz", "/dev/shm/corpus_sample.tar.xz"))
                require(await docker.vmkdir(run, self.target_crash_path.as_posix()))

                @requireable
                async def untar(tarball: str, dst: str) -> Result[None]:
                    require(await docker.vmkdir(run, dst))
                    async with run.exec_scoped("tar", "-xf", tarball, "-C", dst, ".") as proc:
                        _ = await proc.communicate()
                        if proc.returncode != 0:
                            return Err(CRSError(f"could not extract {tarball}"))
                    return Ok(None)

                # untar our samples
                require(await untar("/dev/shm/corpus_sample.tar.xz", "/tmp/corpus_sample/"))

                # if the fuzzer has no default max_len, set it to 64k
                # several fuzzers have issues at that length when they block on pipe
                # we use large corpus files that libfuzzer may not otherwise have generated,
                # so we need to be careful here
                extra_opts: dict[str, Any] = {}
                match await docker.vread(run, f"/out/{self.harness.name}.options"):
                    case Ok(res):
                        if b"max_len" not in res:
                            extra_opts["max_len"] = 65535
                    case _:
                        extra_opts["max_len"] = 65535

                # launch merge jobs in parallel -- merge doesn't do parallelism itself :(
                cores = run.scope.host.cores
                if self.project.info.language == "jvm":
                    cores //= 2
                cores = max(1, cores)
                sem = asyncio.Semaphore(cores)

                @requireable
                async def merge(dst: str, *src: str) -> Result[None]:
                    require(await docker.vmkdir(run, dst))
                    async with invoke(
                        run,
                        self.harness.name,
                        {"merge": 1, "timeout": 1, "artifact_prefix": self.target_crash_path.as_posix() + "/", **extra_opts},
                        FuzzType.Merge,
                        dst,
                        *src,
                    ) as proc:
                        stdout, stderr = await proc.communicate()
                        if proc.returncode != 0:
                            logger.error(f"corpus match libfuzzer merge failed. stdout/stderr:\n{stdout!r}\n{stderr!r}")
                            return Err(CRSError("corpus match libfuzzer merge failed"))
                    return Ok(None)

                async def sem_merge(dst: str, *src: str):
                    async with sem:
                        return await merge(dst, *src)

                handled: list[str] = []
                async with asyncio.TaskGroup() as tg:
                    # our samples are partitioned into 16, run each of those with 1/N of our cores
                    chunk = max(1, math.ceil(16//cores))
                    for i in range(0, 16, chunk):
                        to_handle = "abcdef0123456789"[i:i+chunk]
                        _ = tg.create_task(
                            sem_merge(f"/tmp/merged_{to_handle}", *[f"/tmp/corpus_sample/{c}" for c in to_handle]),
                            name=f"match_corpus() sem_merge({to_handle!r}) project={self.project.name}",
                        )
                        handled.append(to_handle)

                # do another merge to combine our corpus matching seeds AND any fuzzer seeds
                require(await self.untar_to_docker(run, self.seeds.copy()))
                require(await merge(self.target_seed_path.as_posix(), *[f"/tmp/merged_{partitions}" for partitions in handled]))

                # TODO: can we use stats about actual coverage to help decide to include things?

                # list the merged seeds--those sourced from our corpus have names tying them back to their sources
                corpuses: list[tuple[str, str]] = []
                seed_map = await get_seed_map()
                for seed in await docker.vls(run, self.target_seed_path.as_posix()):
                    if info := seed_map.get(seed):
                        corpuses.append((info[0], info[1]))

                @requireable
                async def fetch_corpus_and_merge(collection: str, kind: str) -> Result[None]:
                    require(await azcopy(
                            f"{CRS_BLOB_ENDPOINT}/crs/corpus/{collection}/{kind}.tar.xz",
                            f"/tmp/{collection}__{kind}.tar.xz"
                    ))
                    require(await untar(f"/tmp/{collection}__{kind}.tar.xz", f"/tmp/corpus_{collection}__{kind}"))
                    require(await docker.vmkdir(run, f"/tmp/corpus_{collection}__{kind}_min"))
                    return await sem_merge(f"/tmp/corpus_{collection}__{kind}_min", f"/tmp/corpus_{collection}__{kind}")

                if time.perf_counter() - start > CORPUS_MATCH_SLOW:
                    match_count = CORPUS_MATCH_SLOW_MAX
                else:
                    match_count = CORPUS_MATCH_MAX
                matches = Counter(corpuses).most_common(match_count)

                logger.info(f"corpus matches {self.project.name}/{self.harness.name}: {matches}")
                # pull down those corpuses and merge each...
                async with asyncio.TaskGroup() as tg:
                    for (collection, kind), _ in matches:
                        _ = tg.create_task(
                            fetch_corpus_and_merge(collection, kind),
                            name=f"fetch_corpus_and_merge({collection!r}, {kind!r}) project={self.project.name}",
                        )

                # and then do our final merge
                require(await merge(
                    self.target_seed_path.as_posix(),
                    *[f"/tmp/corpus_{corpus[0]}__{corpus[1]}_min" for corpus, _ in matches]
                ))

                # copy out seeds from this that we don't know about
                seeds = await docker.vls(run, self.target_seed_path.as_posix())
                new = [(self.target_seed_path/seed).as_posix() for seed in seeds if seed not in self.seeds]
                new_seeds = require(await docker.vread_many(run, new))
                _ = await asyncio.gather(*(
                    self.add_seed(data, os.path.basename(seed))
                    for seed, data in new_seeds.items()
                ))

                _ = await self.seed_path.with_suffix(".checkpoint").write_text(str(len(self.seeds)))
                self.last_min_size = len(self.seeds)

                # check if any crashes fell out
                crashes = await self.grab_crashes(run)
                return Ok(([os.path.basename(s) for s in new_seeds], crashes))
        except TimeoutError:
            return Err(CRSError("corpus match timed out"))

    @telem_tracer.start_as_current_span("fuzz_minimize", record_exception=False)
    @requireable
    async def minimize(self, artifacts: BuildArtifacts) -> Result[dict[str, bytes]]:
        logger.debug("starting minimization")
        async with self.minimizing_lock:
            try:
                async with artifacts.run(timeout=MINIMIZE_TIMEOUT, group=docker.DockerGroup.Misc) as run:
                    # set up seed directories
                    require(await docker.vmkdir(run, "/tmp/merged"))
                    require(await docker.vmkdir(run, self.target_crash_path.as_posix()))
                    # if minimizing is slow, more seeds might come in while we're minimizing,
                    # therefore, copy off the known seeds beforehand, and only remove from the minset those
                    # which we knew BEFORE and wanted to remove. It's not a big deal if a new one comes in
                    # before the tar was made--we just won't delete it
                    known_seeds = self.seeds.copy()
                    require(await self.untar_to_docker(run, known_seeds))

                    async with invoke(
                        run,
                        self.harness.name,
                        {"set_cover_merge": 1, "artifact_prefix": self.target_crash_path.as_posix() + "/"},
                        FuzzType.Merge,
                        "/tmp/merged",
                        self.target_seed_path.as_posix(),
                    ) as proc:
                        stdout, stderr = await proc.communicate()
                        if proc.returncode != 0:
                            logger.error(f"libfuzzer merge failed. stdout/stderr:\n{stdout!r}\n{stderr!r}")
                            return Err(CRSError("libfuzzer merge failed"))

                    # grab the merged seeds--names will suffice because the data must have come from our seed dir
                    keep_seeds = await docker.vls(run, "/tmp/merged")

                    stale = known_seeds - keep_seeds
                    logger.debug(f"minimization kept {len(keep_seeds)}, removed {len(stale)} seeds")
                    span = trace.get_current_span()
                    span.add_event(
                        "minimized corpus",
                        attributes={
                            "crs.action.target.harness": self.harness.name,
                            "fuzz.corpus.size": len(keep_seeds),
                        }
                    )
                    to_remove = {s for s in stale if not s.endswith("_nodelete")}
                    await batch_unlink(*[str(self.seed_path / s) for s in to_remove], missing_ok=True)
                    self.seeds -= to_remove

                    crashes = await self.grab_crashes(run)

                _ = await self.seed_path.with_suffix(".checkpoint").write_text(str(len(self.seeds)))
                self.last_min_size = len(self.seeds)
                seed_gauge.set(len(self.seeds), self.telem_attrs)
                return Ok(crashes)
            except TimeoutError:
                return Err(CRSError("minimization timed out"))

    async def add_seeds_bulk(self, seeds: Iterable[tuple[bytes, str]]):
        def inner():
            new_seeds: set[str] = set()
            for seed_dat, seed_name in seeds:
                _ = open(self.seed_path / seed_name, "wb").write(seed_dat)
                new_seeds.add(seed_name)
            return new_seeds
        self.seeds |= await asyncio.to_thread(inner)
        seed_gauge.set(len(self.seeds), self.telem_attrs)

    async def add_seed(self, data: bytes, sha1sum: Optional[str] = None, never_minimize: bool = False):
        if sha1sum is None:
            sha1sum = sha1(data).hexdigest()
        if never_minimize:
            sha1sum += "_nodelete"
        _ = await (self.seed_path / sha1sum).write_bytes(data)
        self.seeds.add(sha1sum)
        seed_gauge.set(len(self.seeds), self.telem_attrs)

    async def add_crash(self, data: bytes, dedup: str, sha1sum: Optional[str] = None) -> bool:
        # if maybe not path safe, run a sha1. Just makes it less nice to read for humans
        if len(dedup) > 64 or re.search("[^a-zA-Z0-9_|+:~<>.,-=]", dedup):
            dedup = sha1(dedup.encode()).hexdigest()

        if not dedup:
            dedup = "UNKNOWN"

        if dedup not in self.crash_buckets or len(self.crash_buckets[dedup]) < MAX_CRASHES_PER_BUCKET:
            if sha1sum is None:
                sha1sum = sha1(data).hexdigest()

            await (self.crash_path / dedup).mkdir(exist_ok=True)
            _ = await (self.crash_path / dedup / sha1sum).write_bytes(data)

            self.crash_buckets[dedup] = self.crash_buckets.get(dedup, [])
            self.crash_buckets[dedup].append(sha1sum)
            self.crashes.add(sha1sum)
            crash_gauge.set(len(self.crashes), self.telem_attrs)

            span = trace.get_current_span()
            span.add_event(
                f"crash found: {sha1sum}",
                attributes={
                    "crs.action.target.harness": self.harness.name,
                    "crs.debug.crash.dedupe": dedup,
                }
            )
            return True
        else:
            logger.info(f"ignoring yet another crash in {dedup} bucket")
            return False

class FuzzOverwatcher:
    def __init__(self, machines: int, cores: int):
        self.machines = machines
        self.cores = cores

        self.cancellable: set[asyncio.Task[Any]] = set()
        self.running_fuzzers = 0

        self.active_fuzzers: list['FuzzManager'] = []
        self.jobs_change = asyncio.Condition()
        self.epoch = 0
        self.rebalancing = False

    def task_core_share(self, fm: 'FuzzManager'):
        base = max(1, (self.cores * self.machines) // self.running_fuzzers)
        if (remaining := (self.cores * self.machines) - (base * self.running_fuzzers)) > 0:
            # we have extra cores from rounding errors we can hand out up to 1 more per fuzzer
            if self.active_fuzzers.index(fm) >= (self.running_fuzzers - remaining):
                base += 1
        return base

    def task_cores_per_job(self, fm: 'FuzzManager', nharnesses: int):
        # we can't launch tasks with that many cores, truncate
        if self.task_core_share(fm) // nharnesses > self.cores:
            return max(1, self.cores)

        # we need time slicing, run on a "couple" cores each
        # (run on half the cores/box unless that is bigger than 4 or < 1)
        if self.task_core_share(fm) < nharnesses:
            return max(1, min(4, self.cores // 2))

        share = max(1, self.task_core_share(fm) // nharnesses)
        # if these allocations don't divide a box nicely (like 17 cores on 32 core boxes)
        # then we need to make them smaller
        while self.cores % share != 0:
            share -= 1
        return share

    @contextlib.asynccontextmanager
    async def activate_fuzzer(self, fm: 'FuzzManager'):
        async def cleanup():
            async with self.jobs_change:
                self.running_fuzzers -= 1
                self.active_fuzzers.remove(fm)
                self.epoch += 1
                self.jobs_change.notify_all()

        async with finalize(cleanup()):
            async with self.jobs_change:
                self.running_fuzzers += 1
                self.active_fuzzers.append(fm)
                # re-balance running fuzzers
                self.epoch += 1
                self.jobs_change.notify_all()
            yield

fuzzoverwatcher = FuzzOverwatcher(machines=int(os.environ.get("CRS_FUZZER_COUNT", 0)), cores=int(os.environ.get("CRS_FUZZER_CORES", 0)))

class FuzzHarnessManager:
    def __init__(self, manager: 'FuzzManager', task: Task, harness_num: int, harness: Harness, build_artifacts: BuildArtifacts, corpus_manager: CorpusManager, primary: bool = True):
        self.manager = manager
        self.task = task
        self.harness_num = harness_num
        self.harness = harness
        self.build_artifacts = build_artifacts
        self.corpus_manager = corpus_manager
        self.minimizing_task: Optional[asyncio.Task[Any]] = None
        self.known_crashes: set[str] = set()
        self.known_seeds = self.corpus_manager.seeds.copy()
        self.primary = primary
        self.ran_corpus_match = False

        self.stack_hash_counts: dict[str, int] = defaultdict(int)

    async def on_seed_found(self, name: str):
        if name in self.manager.known_seeds:
            return
        self.manager.known_seeds.add(name)
        for callback in self.manager.seed_callbacks:
            await callback(self.harness_num, name)
            seed_callbacks_counter.add(1, self.corpus_manager.telem_attrs)

    async def minimize_with_crashes(self):
        match await self.corpus_manager.minimize(self.build_artifacts):
            case Ok(crashes):
                _ = await asyncio.gather(*(self.on_crash_found(name, contents)
                                           for name, contents in crashes.items()))
            case _:
                pass

    async def on_crash_found(self, name: str, contents: bytes):
        local_path = self.corpus_manager.untested_crash_path / name
        _ = await local_path.write_bytes(contents)

        if name in self.manager.known_crashes:
            return
        self.manager.known_crashes.add(name)

        for callback in self.manager.triage_callbacks:
            await callback(self.harness_num, local_path.as_posix())
            crash_callbacks_counter.add(1, self.corpus_manager.telem_attrs)

    async def wipe_stale_seeds(self, run: docker.DockerRun):
        current_seeds = await docker.vls(run, self.corpus_manager.target_seed_path.as_posix())
        to_remove = current_seeds - self.corpus_manager.seeds

        # note that we may have enough things to remove that this exceeds OS limits on cli lengths, so we
        # need to do something fancier than passing all paths as an arg
        match await docker.vrm_many(run, [(self.corpus_manager.target_seed_path / seed).as_posix() for seed in to_remove]):
            case Err() as e:
                logger.warning(f"failed to rm stale seeds: {e}")
            case Ok():
                pass

        res = await docker.vrm(run, self.corpus_manager.target_crash_path.as_posix())
        if res.is_err():
            logger.warning(f"failed to rm stale crashes: {res}")
        res = await docker.vmkdir(run, self.corpus_manager.target_crash_path.as_posix())
        if res.is_err():
            logger.error(f"failed to mkdir crashes folder: {res}")

    async def _inner_fuzz_loop(
        self,
        run: docker.DockerRun,
        taskgroup: asyncio.TaskGroup,
        workers: int = 1,
    ) -> Result[None]:
        logger.debug("starting fresh inner fuzzer")

        # jazzer takes up > 1 cpu in overhead, so launch fewer jobs
        if self.task.project.info.language.lower() == "jvm":
            workers = max(1, workers//2)

        # just fuzz for a bit. This allows minsetting to remove cruft
        args = {
            "detect_leaks": 0,
            "max_total_time": SINGLE_FUZZER_TIMEOUT,
            "fork": 1, # needed to continue operating after crashes are identified
            "ignore_crashes": 1, # ignore means "don't exit when you see one"
            "artifact_prefix": self.corpus_manager.target_crash_path.as_posix() + "/",
            "jobs": workers,
            "workers": workers,
        }

        async def launch_python_background(n: int):
            proc = None
            try:
                async with asyncio.timeout(SINGLE_FUZZER_TIMEOUT + FUZZER_GRACE_PERIOD):
                    # look for fuzz-n.log in /out/
                    async with run.exec_scoped(
                        "python3", "/usr/local/bin/dedup_mon.py", f"/out/fuzz-{n}.log",
                        stdout=DEVNULL, stderr=DEVNULL
                    ) as proc:
                        if await proc.wait() != 0:
                            logger.error(f"dedup_mon exited")
            except TimeoutError:
                pass
            finally:
                if proc:
                    proc.kill()

        project_name = self.task.project.name
        cleanup_tasks: list[asyncio.Task[Any]] = []
        try:
            async with asyncio.timeout(SINGLE_FUZZER_TIMEOUT + FUZZER_GRACE_PERIOD):
                if self.task.project.info.language != "jvm":
                    async with run.exec_scoped(
                        "perl",
                        "-pi",
                        "-e",
                        r"s/\0ERROR:\0runtime error:\0/\0EDUP_T\0ritten to \0xxx\0/g",
                        f"/out/{self.harness.name}"
                    ) as proc:
                        if await proc.wait() != 0:
                            logger.error("libfuzzer binary patch failed")

                    for i in range(workers):
                        cleanup_tasks.append(taskgroup.create_task(launch_python_background(i), name=f"python_background({i}) project={project_name}"))

                async with invoke(
                    run,
                    self.harness.name,
                    args,
                    FuzzType.JVM if self.task.project.info.language == "jvm" else FuzzType.C,
                    self.corpus_manager.target_seed_path.as_posix(),
                ) as proc:
                    while proc.returncode is None:
                        # scan for new seeds to add to our corpus
                        current_seeds = await docker.vls(run, self.corpus_manager.target_seed_path.as_posix())
                        # ignore "known seeds" we produced, but may have been removed from the minset
                        new_seeds = current_seeds - self.corpus_manager.seeds - self.known_seeds

                        logger.debug(f"{len(new_seeds)} new seeds from fuzzer")
                        match await docker.vread_many(
                            run,
                            [(self.corpus_manager.target_seed_path / seed).as_posix() for seed in new_seeds],
                            ignore_allowed=True,
                        ):
                            case Err() as e:
                                logger.warning(f"failed to read new seeds from fuzzer: {e}")
                            case Ok(seed_dict):
                                if len(seed_dict):
                                    await self.corpus_manager.add_seeds_bulk(
                                        (seed_data, os.path.basename(seed_path)) for seed_path, seed_data in seed_dict.items()
                                    )
                                    for seed_path in seed_dict:
                                        seed_name = os.path.basename(seed_path)
                                        self.known_seeds.add(seed_name)
                                        _ = taskgroup.create_task(self.on_seed_found(seed_name), name=f"on_seed_found({seed_name}) project={project_name}")

                                    logger.info(f"added {len(seed_dict)} new seeds to {project_name}:{self.task.task_id}")
                                    seed_counter.add(len(seed_dict), self.corpus_manager.telem_attrs)

                        if self.primary and self.corpus_manager.should_minimize():
                            if (not self.minimizing_task) or (self.minimizing_task.done()):
                                self.minimizing_task = taskgroup.create_task(self.minimize_with_crashes(), name=f"minimize_with_crashes() project={project_name}")

                        # check for new seeds in the corpus
                        if self.corpus_manager.seeds - current_seeds:
                            logger.debug(f"syncing {len(self.corpus_manager.seeds - current_seeds)} new seeds into fuzzer")
                            _ = await self.corpus_manager.untar_to_docker(run, self.corpus_manager.seeds - current_seeds)

                        # check for crashes
                        crashes = await docker.vls(run, self.corpus_manager.target_crash_path.as_posix())
                        # filter out crashes we've already examined
                        new_crashes = {x for x in crashes if x.split(".")[0] not in self.known_crashes}
                        logger.debug(f"{project_name}: {len(crashes)} crashes in folder; {len(new_crashes)} unseen")

                        # filter out crashes with too common dedup tokens
                        dedupe_map = dict(x.split(".") for x in new_crashes if "." in x)
                        new_crashes = {
                            x for x in new_crashes
                            if "." not in x and
                            self.stack_hash_counts[dedupe_map.get(x, "")] < MAX_CRASHES_PER_BUCKET * 2
                        }
                        logger.debug(f"{project_name}: and {len(new_crashes)} after dedupe stuff? {self.stack_hash_counts}")

                        match await docker.vread_many(
                            run,
                            [(self.corpus_manager.target_crash_path / crash).as_posix() for crash in new_crashes],
                        ):
                            case Err() as e:
                                logger.error(f"serious error occured when trying to read crashes: {e}")
                            case Ok(crash_files):
                                for name, data in crash_files.items():
                                    basename = os.path.basename(name)
                                    _ = taskgroup.create_task(self.on_crash_found(basename, data), name=f"on_crash_found({basename}) project={project_name}")
                                    if (dedupe_token := dedupe_map.get(basename)):
                                        self.stack_hash_counts[dedupe_token] += 1
                                    self.known_crashes.add(basename)
                                if len(crash_files):
                                    logger.info(f"added {len(crash_files)} new crashes to {project_name}:{self.task.task_id}")
                                    crash_counter.add(len(crash_files), self.corpus_manager.telem_attrs)

                        # don't delay if the process exited early
                        try:
                            _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                        except TimeoutError:
                            pass
                    if proc.returncode == 0:
                        return Ok(None)
                    else:
                        return Err(CRSError(f"fuzzer process not cleanly exiting (status {proc.returncode})"))
        except TimeoutError:
            logger.warning(f"{project_name}:{self.task.task_id} timing out")
            return Ok(None)
        finally:
            for task in cleanup_tasks:
                _ = task.cancel()

    @requireable
    async def do_unzip(self, run: docker.DockerRun) -> Result[None]:
        seeds_before = await docker.vls(run, self.corpus_manager.target_seed_path.as_posix())
        inner_cmd = (
            f"if [ -f $OUT/{self.harness.name}_seed_corpus.zip ]; then "
            f"unzip -o -q -d /tmp/zip_corpus $OUT/{self.harness.name}_seed_corpus.zip; "
            f"""find /tmp/zip_corpus -type f -exec sh -c 'mv "$1" "{self.corpus_manager.target_seed_path.as_posix()}/$(sha1sum "$1" | awk "{{print \\$1}}")"' _ {{}} \\; ;"""
            "fi"
        )
        async with run.exec_scoped("bash", "-c", inner_cmd, stdout=PIPE, stderr=STDOUT) as proc:
            output, _ = await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"failed to try unzipping seeds: {output!r}")
        seeds_after = await docker.vls(run, self.corpus_manager.target_seed_path.as_posix())

        for seed, data in require(await docker.vread_many(
            run,
            {(self.corpus_manager.target_seed_path / s).as_posix() for s in seeds_after - seeds_before}
        )).items():
            _ = await (self.corpus_manager.seed_path / os.path.basename(seed)).write_bytes(data)

        return Ok(None)

    async def gather_local_seeds(self, run: docker.DockerRun):
        async with CACHE_DIR.glob(f"data/*/{self.task.project.name}/seeds_{self.harness.name}_*") as seed_it:
            async for seed_dir in seed_it:
                if not await seed_dir.is_dir():
                    continue
                if self.corpus_manager.seed_path == seed_dir:
                    continue
                # we found a _different_ seed dir for the same project and harness! use it
                seed_dir_sync = await seed_dir.sync()
                def copy_seeds():
                    seeds: set[str] = set()
                    for f in seed_dir_sync.iterdir():
                        seeds.add(f.name)
                        try:
                            _ = shutil.copy(f, self.corpus_manager.seed_path)
                        except (OSError, FileNotFoundError):
                            pass
                    return seeds
                self.corpus_manager.seeds |= await asyncio.to_thread(copy_seeds)

        async with CACHE_DIR.glob(f"data/*/{self.task.project.name}/crashes_{self.harness.name}_*") as crash_it:
            async for crash_dir in crash_it:
                if not await crash_dir.is_dir():
                    continue
                if self.corpus_manager.crash_path == crash_dir:
                    continue
                # we found a _different_ crash dir for the same project and harness! use it
                crash_dir_sync = await crash_dir.sync()
                def copy_crashes():
                    seeds: set[str] = set()
                    for cluster in crash_dir_sync.iterdir():
                        if not cluster.is_dir():
                            continue
                        for f in cluster.iterdir():
                            seeds.add(f.name)
                            try:
                                _ = shutil.copy(f, self.corpus_manager.seed_path)
                            except (OSError, FileNotFoundError):
                                pass
                    return seeds
                self.corpus_manager.seeds |= await asyncio.to_thread(copy_crashes)

    @telem_tracer.start_as_current_span("fuzz_one_harness", record_exception=False)
    async def run_harness_task(
        self,
        sem: asyncio.Semaphore,
        contention: bool,
        workers: int = 1,
    ):
        """
        Note: runs unbounded and assumes the caller has an asyncio.Timeout to manage this
        """
        first_run = self.primary

        project_name = self.task.project.name
        attrs = {
            "task": str(self.task.task_id),
            "project": project_name,
            "harness": self.harness.name,
            "sanitizer": self.build_artifacts.build_config.SANITIZER,
        }
        async with (time_counter_block(fuzz_time_counter, attributes=attrs),
                    asyncio.TaskGroup() as background_taskgroup):

            @async_once
            async def match_corp_once():
                if not self.primary or self.ran_corpus_match:
                    return
                self.ran_corpus_match = True
                try:
                    match await self.corpus_manager.match_corpus(self.build_artifacts):
                        case Ok((seeds, crashes)):
                            for seed in seeds:
                                _ = background_taskgroup.create_task(self.on_seed_found(seed), name=f"on_seed_found({seed!r}) project={project_name}")
                            if crashes:
                                logger.info(f"found {len(crashes)} potential crashes from corpus match!")
                            for crash_name, crash_data in crashes.items():
                                _ = background_taskgroup.create_task(self.on_crash_found(crash_name, crash_data), name=f"on_crash_found({crash_name!r}) project={project_name}")
                            logger.info(f"corpus match completed for {project_name}/{self.harness.name}")
                        case Err() as e:
                            logger.warning(f"corpus match failed on {project_name}/{self.harness.name}: {e}")
                except Exception as e:
                    logger.error(f"fatal error in corpus matching: {e}")

            while True:
                # this should only run inside a timeout
                async with sem, self.build_artifacts.run(mounts={CRS_DEDUP_MON: "/usr/local/bin/dedup_mon.py"}, timeout=None, group=docker.DockerGroup.Fuzz, cores=workers) as run:
                    _ = await docker.vmkdir(run, self.corpus_manager.target_seed_path.as_posix())
                    _ = await docker.vmkdir(run, self.corpus_manager.target_crash_path.as_posix())

                    # on the first run, unzip any seed zips that are available and put them in our corpus dir
                    # not super painful to repeat, just unncessary
                    if first_run:
                        old_seeds = self.corpus_manager.seeds.copy()
                        _ = await self.do_unzip(run)
                        await self.gather_local_seeds(run)
                        # update coverage, etc for new seeds added to the corpus
                        async with self.corpus_manager.seed_path.iterdir() as seed_it:
                            async for seed in seed_it:
                                name = seed.name
                                if name in old_seeds:
                                    continue
                                _ = background_taskgroup.create_task(self.on_seed_found(name), name=f"on_seed_found({name!r}) project={project_name}")
                        first_run = False
                    # populate the corpus directory
                    known_seeds = self.corpus_manager.seeds.copy()
                    start_seeds = await docker.vls(run, self.corpus_manager.target_seed_path.as_posix())
                    _ = await self.corpus_manager.untar_to_docker(run, known_seeds - start_seeds)

                    if len(known_seeds) > 100:
                        _ = background_taskgroup.create_task(match_corp_once(), name=f"match_corp_once() (late) project={project_name}")

                    # launch "short" fuzz jobs until our deadline is done
                    while True:
                        match await self._inner_fuzz_loop(run, background_taskgroup, workers=workers):
                            case Err():
                                # re-run the docker, give it a second to avoid tight error loops
                                await asyncio.sleep(1)
                                break
                            case Ok():
                                # re-use existing docker
                                await self.wipe_stale_seeds(run)

                        # wait until we've fuzzed a bit, and then run a corpus match one time
                        _ = background_taskgroup.create_task(match_corp_once(), name=f"match_corp_once() (warmup) project={project_name}")

                        if contention:
                            break


type POVCallback = Callable[[Iterable[tuple[POVTarget, CrashResult, bool]]], Awaitable[None]]
type SeedCallback = Callable[[int, str], Awaitable[None]]
type TriageCallback = Callable[[int, str], Awaitable[None]]
class FuzzManager:
    def __init__(self, task: Task):
        self.task = task
        self.crash_callbacks: list[POVCallback] = []
        self.seed_callbacks: list[SeedCallback] = []
        self.triage_callbacks: list[TriageCallback] = []
        self._corpus_managers: dict[Harness, CorpusManager] = {}
        self.known_crashes: set[str] = set()
        self.known_seeds: set[str] = set()

    def add_crash_callback(self, callback: POVCallback):
        self.crash_callbacks.append(callback)
        logger.info(f"{self.task.project.name}:{self.task.task_id} now has {len(self.crash_callbacks)} crash callbacks")

    def add_seed_callback(self, callback: SeedCallback):
        self.seed_callbacks.append(callback)
        logger.info(f"{self.task.project.name}:{self.task.task_id} now has {len(self.crash_callbacks)} seed callbacks")

    def add_triage_callback(self, callback: TriageCallback):
        self.triage_callbacks.append(callback)
        logger.info(f"{self.task.project.name}:{self.task.task_id} now has {len(self.crash_callbacks)} triage callbacks")

    async def on_crashes(self, crashes: Iterable[tuple[Harness, CrashResult]]):
        # notify the relevant corpus manager
        async def add_crash(harness: Harness, crash: CrashResult) -> bool:
            cm = await self.get_corpus_manager(harness)
            return await cm.add_crash(crash.input, crash.dedup)
        is_new = await asyncio.gather(*(add_crash(harness, crash) for harness, crash in crashes))
        params = [
            (
                POVTarget(
                    task_uuid=self.task.task_id,
                    project_name=self.task.project.name,
                    harness=harness.name,
                    sanitizer=crash.config.SANITIZER,
                    engine=crash.config.FUZZING_ENGINE,
                ),
                crash,
                is_new,
            ) for (harness, crash), is_new in zip(crashes, is_new)
        ]
        for callback in self.crash_callbacks:
            await callback(params)

    async def get_corpus_manager(self, harness: Harness):
        if harness not in self._corpus_managers:
            # always use CorpusManager for primary build config
            build_config = self.task.project.info.build_configs[0]
            cm = CorpusManager(self.task.project, harness, build_config)
            await cm.init()
            self._corpus_managers[harness] = cm
        return self._corpus_managers[harness]

    @alru_cache(maxsize=None, filter=only_ok)
    async def get_fuzzers(self) -> Result[dict[str, dict[Harness, FuzzHarnessManager]]]:
        match await self.task.project.init_harness_info():
            case Ok(harnesses):
                pass
            case Err() as e:
                logger.error(f"could not init harnesses for fuzzing: {e}")
                return Err(CRSError(f"could not init harnesses for fuzzing: {e}"))

        res: dict[str, dict[Harness, FuzzHarnessManager]] = {}
        primary = True
        for build_config in self.task.project.info.build_configs:
            match await self.task.project.build(build_config):
                case Ok(artifacts):
                    pass
                case Err() as e:
                    logger.error(f"could not init default artifacts for fuzzing: {e}")
                    return Err(CRSError(f"could not init default artifacts for fuzzing: {e}"))

            res[build_config.SANITIZER] = {
                harness: FuzzHarnessManager(
                    self, self.task, i, harness, artifacts,
                    corpus_manager=await self.get_corpus_manager(harness), primary=primary,
                ) for i, harness in enumerate(harnesses)
            }

            # only the first build config is "primary"
            primary = False
        return Ok(res)

    @telem_tracer.start_as_current_span(
        "fuzz_all_harnesses",
        attributes={"crs.action.category": "fuzzing"},
        record_exception=False,
    )
    async def run(self):
        fuzzers = (await self.get_fuzzers()).unwrap()
        primary_fuzzers = list(fuzzers.values())[0]
        secondary_fuzzer_count = sum(len(x) for x in list(fuzzers.values())[1:])

        max_secondary_jobs = min(MAX_SECONDARY_FUZZ_JOBS, secondary_fuzzer_count)

        async with fuzzoverwatcher.activate_fuzzer(self):
            async with asyncio.TaskGroup() as fuzzer_group:
                while True:
                    epoch = fuzzoverwatcher.epoch
                    core_share = fuzzoverwatcher.task_core_share(self)
                    secondary_jobs = 0
                    # no more than 1/3 the cores for other sanitizer jobs
                    if len(fuzzers) > 1:
                        secondary_jobs = max(1, min(core_share//3, max_secondary_jobs))

                    allocated = 0
                    # remaining cores go to primary sanitizer fuzzer
                    cores_available = max(1, core_share - secondary_jobs)

                    # cores for secondary is whatever is left over
                    secondary_cores_available = core_share - cores_available

                    cores_per_job = fuzzoverwatcher.task_cores_per_job(self, len(primary_fuzzers))
                    # limit how many big chunks we try to do at once
                    primary_semaphore = asyncio.Semaphore(cores_available // cores_per_job)
                    # limit the number of small chunks we do at once
                    small_gaps = cores_available - cores_per_job * (cores_available // cores_per_job)

                    # if we have dedicated cores left over for other sanitizers, share amongst those
                    sanitizer_contention = False
                    if secondary_cores_available or secondary_fuzzer_count == 0:
                        secondary_semaphore = asyncio.Semaphore(secondary_cores_available)
                    # otherwise we need to contend with the primary cores
                    else:
                        secondary_semaphore = primary_semaphore
                        sanitizer_contention = True

                    tasks: list[asyncio.Task[Any]] = []

                    # first pass for primary fuzzers
                    # if we have a lot of machines with small numbers of cores, we may need to launch
                    # lots of things to take advantage of the cores
                    while cores_available >= cores_per_job:
                        # the contention can differ per pass
                        contention = sanitizer_contention or (cores_per_job * len(primary_fuzzers)) > cores_available
                        for harness, fuzzer in primary_fuzzers.items():
                            logger.info(f"running workers for {harness.name} with {cores_per_job} {contention=}")
                            tasks.append(
                                fuzzer_group.create_task(
                                    fuzzer.run_harness_task(primary_semaphore, contention, workers=cores_per_job),
                                    name=f"run_harness_task() (primary) project={self.task.project.name}",
                                )
                            )
                            allocated += cores_per_job
                            cores_available -= cores_per_job

                    # we need to fill in "gaps" with primary jobs
                    # do it one size at a time to prefer larger sized jobs
                    while small_gaps > 0:
                        alloc_size = max(1, small_gaps // len(primary_fuzzers))
                        # must be divisible by number of cores for nice scheduling
                        while fuzzoverwatcher.cores % alloc_size != 0:
                            alloc_size -= 1

                        contention = alloc_size * len(primary_fuzzers) > small_gaps
                        gap_sem = asyncio.Semaphore(small_gaps // alloc_size)
                        while small_gaps > 0:
                            for harness, fuzzer in primary_fuzzers.items():
                                logger.info(f"running workers for {harness.name} with {alloc_size} {contention=} [gap]")
                                tasks.append(
                                    fuzzer_group.create_task(
                                        fuzzer.run_harness_task(gap_sem, contention, workers=alloc_size),
                                        name=f"run_harness_task() (gap) project={self.task.project.name}",
                                    )
                                )
                                allocated += alloc_size
                                small_gaps -= alloc_size

                    contention = sanitizer_contention or secondary_fuzzer_count > secondary_cores_available
                    for sanitizer, secondary_fuzzers in list(fuzzers.items())[1:]:
                        for harness, fuzzer in secondary_fuzzers.items():
                            logger.info(f"running workers for {harness.name} {sanitizer=} with 1 {contention=}")
                            tasks.append(
                                fuzzer_group.create_task(
                                    fuzzer.run_harness_task(secondary_semaphore, contention, workers=1),
                                    name=f"run_harness_task() (secondary) project={self.task.project.name}",
                                )
                            )
                            allocated += 1
                    async with fuzzoverwatcher.jobs_change:
                        while epoch == fuzzoverwatcher.epoch:
                            _ = await fuzzoverwatcher.jobs_change.wait()
                    await asyncio.sleep(REBALANCE_COOLDOWN)
                    for task in tasks:
                        _ = task.cancel()


    @requireable
    async def add_seed_by_num(self, harness_num: int, contents: bytes, never_minimize: bool = False) -> Result[None]:
        """
        Add a seed to the fuzzing corpus for the given harness. Usually because we have some reason
        (such as LLM tool operation) to suggest it is a useful seed
        """
        harnesses = require(await self.task.project.init_harness_info())
        if harness_num >= len(harnesses):
            return Err(CRSError(f"invalid harness num {harness_num} (max {len(harnesses)-1})"))
        return await self.add_seed(harnesses[harness_num], contents, never_minimize=never_minimize)

    @requireable
    async def add_seed(self, harness: Harness, contents: bytes, never_minimize: bool = False) -> Result[None]:
        """
        Add a seed to the fuzzing corpus for the given harness. Usually because we have some reason
        (such as LLM tool operation) to suggest it is a useful seed
        """
        logger.info("adding fuzzer seed")
        await (await self.get_corpus_manager(harness)).add_seed(contents, never_minimize=never_minimize)
        return Ok(None)

    @requireable
    async def get_corpus_by_num(self, harness_num: int, max_files: int) -> Result[dict[str, bytes]]:
        _ = require(await self.task.project.init_harness_info())
        harness = require(self.task.project.check_harness(harness_num))
        return await self.get_corpus(harness, max_files=max_files)

    @requireable
    async def get_corpus(self, harness: Harness, max_files: int) -> Result[dict[str, bytes]]:
        logger.debug("get corpus")
        corpus_manager = await self.get_corpus_manager(harness)
        seed_path = await corpus_manager.seed_path.sync()

        def read_files():
            seeds: dict[str, bytes] = {}
            for seed in corpus_manager.seeds.copy():
                if len(seeds) >= max_files:
                    return seeds
                path = seed_path / seed
                if not path.exists():
                    continue
                try:
                    seeds[seed] = path.read_bytes()
                except OSError:
                    pass
            return seeds

        seeds = await asyncio.to_thread(read_files)

        return Ok(seeds)
