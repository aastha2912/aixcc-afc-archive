# this reads the main information about a problem (name, language, repos, etc)
# and provides the basics for interacting with a problem (building, patching, etc)
from asyncio.subprocess import PIPE, STDOUT
import asyncio
import base64
from collections import defaultdict
import contextlib
from datetime import datetime, timezone
from enum import Enum, auto
from dataclasses import dataclass, field
from hashlib import sha256
import orjson
import os
from crs.common.aio import Path
from pydantic import BaseModel, ConfigDict, field_serializer, field_validator, computed_field
import re
from typing import Any, AsyncIterator, Optional, Type, Tuple, Sequence, TYPE_CHECKING
import uuid
import yaml

from crs import config
from crs.common import aio, docker, process, diff_utils
from crs.common.alru import async_once, alru_cache
from crs.common.constants import *
from crs.common.vfs import VFS, EditableOverlayFS, TarFS
from crs.common.types import Result, Ok, Err, CRSError, BuildConfig
from crs.common.utils import cached_property, only_ok, requireable, require, collect, trim_tool_output
from crs.common.vfs.base import MountFS
from crs.modules.python_sandbox import run_python, SANDBOX_IMAGE_NAME
from crs.modules.search_code import Searcher, GTagDB
from crs.modules.source_editor import Editor

from crs_rust import logger

if TYPE_CHECKING:
    from crs.modules.coverage import CoverageAnalyzer
    from crs.modules.debugger import Debugger

API_BASE_URI = os.getenv("AIXCC_API_HOSTNAME", "http://localhost:8082")
PROJECT_YAML_FILE = "project.yaml"
SILENCE_BUILDS = bool(os.getenv("SILENCE_BUILDS", False))

DEDUPE_FRAMES_C = 5
DEDUPE_FRAMES_JAVA = 14

RUNNER_IMAGE = "ghcr.io/aixcc-finals/base-runner-debug:v1.3.0"

POV_BAD_ERROR = "the PoV did not cause a crash"
POV_NO_REPRO = "the PoV did not trigger at HEAD"

DEFAULT_BUILD_TIMEOUT = 60*60
DEFAULT_POV_TIMEOUT = 120
DEFAULT_INIT_TIMEOUT = 4*60*60

DEFAULT_TASK_TIMEOUT = 4*60*60

class CommitRange(BaseModel):
    start_ref: str
    end_ref: str

class ProjectInfo(BaseModel):
    main_repo: str
    language: str
    homepage: str = ""
    primary_contact: str = ""
    auto_ccs: list[str] = []
    vendor_ccs: Optional[list[str]] = None
    sanitizers: list[str] = [DEFAULT_SANITIZER]
    architectures: list[str] = [DEFAULT_ARCHITECTURE]
    fuzzing_engines: list[str] = [DEFAULT_ENGINE]
    help_url: Optional[str] = None
    builds_per_day: Optional[int] = None
    file_github_issue: Optional[bool] = None
    coverage_extra_args: str = ""
    commit_range: Optional[CommitRange] = None # non-standard, added by Theori for testing purposes

    @computed_field
    @cached_property
    def build_configs(self) -> list[BuildConfig]:
        res: list[BuildConfig] = []
        assert DEFAULT_ENGINE in self.fuzzing_engines # for now we only use the default engine
        assert DEFAULT_ARCHITECTURE in self.architectures # only x86_64 is supported
        for san in sorted(self.sanitizers):
            res.append(BuildConfig(
                FUZZING_LANGUAGE=self.language,
                SANITIZER=san,
                ARCHITECTURE=DEFAULT_ARCHITECTURE,
                FUZZING_ENGINE=DEFAULT_ENGINE
            ))
        return res

    @computed_field
    @cached_property
    def default_build_config(self) -> BuildConfig:
        return self.build_configs[0]

    @computed_field
    @cached_property
    def coverage_build_config(self) -> BuildConfig:
        return BuildConfig(
            FUZZING_LANGUAGE=self.language,
            SANITIZER="coverage",
            ARCHITECTURE=self.architectures[0],
            CFLAGS="-fno-inline"
        )

    @computed_field
    @cached_property
    def debug_build_config(self) -> BuildConfig:
        match self.language:
            case "c"|"c++": return BuildConfig(
                FUZZING_LANGUAGE=self.language,
                FUZZING_ENGINE="none",
                SANITIZER=DEFAULT_SANITIZER,
                ARCHITECTURE=self.architectures[0],
                CFLAGS="-ggdb -fno-inline",
            )
            case _: return self.coverage_build_config

    @computed_field
    @cached_property
    def introspector_build_config(self) -> BuildConfig:
        return BuildConfig(
            FUZZING_LANGUAGE=self.language,
            SANITIZER="introspector",
            ARCHITECTURE=self.architectures[0]
        )

class HarnessType(Enum):
    LIBFUZZER = auto()

class Harness(BaseModel):
    name: str
    type: HarnessType
    source: str
    options: str
    harness_func: Optional[str]

    model_config = ConfigDict(frozen=True)

class CrashResult(BaseModel):
    config: BuildConfig
    input: bytes
    output: str
    dedup: str
    stack: str

    # we use CrashResult in our POVProducer result, which gets json.dump'd (even though no one uses it)
    # just do this to be safe
    @field_serializer("input")
    def serialize_bytes(self, data: bytes, _info: Any) -> str:
        return base64.b64encode(data).decode()

    @field_validator("input", mode="before")
    @classmethod
    def deserialize_bytes(cls, value: Any):
        if isinstance(value, str):
            return base64.b64decode(value)
        return value

@requireable
async def _build_project_image(project_dir: Path, image_name: str, timeout: Optional[float]=DEFAULT_INIT_TIMEOUT) -> Result[str]:
    logger.info(f"building project image in {project_dir.as_posix()}...")
    async with docker.scope(timeout=timeout) as scope:
        require(await docker.build_image(scope, project_dir, image_name))
        return await docker.get_image_workdir(scope, image_name)

async def _init_project_data(project_dir: Path, build_image: str, ossfuzz_hash: str) -> tuple[Path, ProjectInfo, str]:
    async def _init_project_data_inner(project_dir: Path, build_image: str, ossfuzz_hash: str) -> tuple[Path, ProjectInfo, str]:
        logger.info(f"initializing data for {project_dir.as_posix()}")
        workdir = (await _build_project_image(project_dir, build_image, timeout=DEFAULT_INIT_TIMEOUT)).expect("project image did not build")

        project_yaml = Path(project_dir / PROJECT_YAML_FILE)
        info = ProjectInfo(**yaml.safe_load(await project_yaml.read_bytes()))
        data_dir = config.CACHE_DIR / "data" / ossfuzz_hash / project_dir.name
        await data_dir.mkdir(parents=True, exist_ok=True)

        tar_path = data_dir / "src.tar"
        if await tar_path.exists():
            return data_dir, info, workdir

        async with docker.run(build_image, mounts={config.CRS_UNPACK_GIT: "/opt/unpack_git.sh"}, timeout=DEFAULT_INIT_TIMEOUT) as run:
            proc = await run.exec("/opt/unpack_git.sh", stdout=PIPE, stderr=STDOUT)
            reader = process.Reader(proc)
            res = await reader.communicate()
            if res.returncode != 0:
                # we only used the unpacked state for test projects, so we don't care if this happens to fail in finals
                logger.warning(f"unpack_git.sh failed: {res.output}")

            exclude_arg = [arg for ex in DEFAULT_FUZZER_DIRS for arg in ["--exclude", ex]]
            docker_tar = [
                "tar", "cf", "-", *exclude_arg, "--transform", r"s/^\.\///", "-C", f"/src", "."
            ]
            async with aio.tmpfile(dir=data_dir, prefix=f"{tar_path.name}.tmp") as tf:
                proc = await run.exec(*docker_tar, stdout=tf)
                if await proc.wait() != 0:
                    raise CRSError(f"failed to docker tar /src")
                await tf.path.replace(tar_path)
        return data_dir, info, workdir

    timeouts = 0
    while True:
        try:
            return await _init_project_data_inner(project_dir, build_image, ossfuzz_hash)
        except TimeoutError:
            timeouts += 1
            backoff = 2 ** timeouts
            logger.error(f"project init timed out ({timeouts}) for {project_dir}, backing off for {backoff}s")
            await asyncio.sleep(backoff)

class BuildError(CRSError):
    pass

class NoTests(CRSError):
    pass

class TestFailure(CRSError):
    pass

class BuildArtifacts:
    def __init__(self, project_name: str, build_config: BuildConfig, build_vfs: VFS):
        self.project_name = project_name
        self.build_config = build_config
        self.build_vfs = build_vfs

    @contextlib.asynccontextmanager
    async def run(
        self,
        env: dict[str, Any] = {},
        mounts: dict[Path, str] = {},
        timeout: Optional[float] = DEFAULT_POV_TIMEOUT,
        group: docker.DockerGroup = docker.DockerGroup.Misc,
        **kwargs: Any,
    ) -> AsyncIterator[docker.DockerRun]:
        logger.debug(f"BuildArtifacts(project={self.project_name!r}, build_config={self.build_config!r}).run()")
        env = env | self.build_config.model_dump()
        async with docker.run(RUNNER_IMAGE, mounts=mounts, env=env, timeout=timeout, group=group, **kwargs) as run:
            # NOTE: ignoring error here because it's really annoying to smuggle through the context manager interface
            # TODO: handle error
            _ = await docker.vwrite_layers(run, "/out", await self.build_vfs.layers())
            yield run

    @requireable
    async def run_pov_inside(
        self,
        run: docker.DockerRun,
        pov_data: bytes,
        harness_name: str,
    ) -> Result[process.Reader]:
        _ = require(await docker.vwrite(run, {"/testcase": pov_data}))
        SAN_OPTIONS = [
            'print_stacktrace=1',
            f"dedup_token_length={DEDUPE_FRAMES_C}",
            'stack_trace_format=\\"Stack Frame #%n %F %L\\"' # see https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/sanitizer_common/sanitizer_stacktrace_printer.h#L67
        ]
        env: list[str] = []
        for san in SANITIZER_VARS:
            env.append(f'{san}="${san}:{":".join(e for e in SAN_OPTIONS)}"')
        env.append('JAVA_OPTS="$JAVA_OPTS;-XX:ActiveProcessorCount=2"')
        cmd = ["bash", "-c", f"{' '.join(env)} reproduce {harness_name}"]
        proc = await run.exec(*cmd, stdout=PIPE, stderr=PIPE)
        return Ok(process.Reader(proc))

    @alru_cache(maxsize=128)
    async def run_pov(
        self,
        pov_data: bytes,
        harness_name: str,
        timeout: float = DEFAULT_POV_TIMEOUT,
        **kwargs: Any,
    ) -> process.ProcRes:
        reader = process.Reader()
        try:
            async with self.run(timeout=timeout, **kwargs) as run:
                match await self.run_pov_inside(run, pov_data, harness_name):
                    case Ok(reader):
                        res = await reader.communicate()
                    case Err(e):
                        return process.ProcRes.dummy_failure(e.error)
        except TimeoutError:
            res = reader.result(timedout=True)
        return res

def _build_image_name(project_name: str, ossfuzz_hash: str) -> str:
    image = f"{project_name}:{ossfuzz_hash}"
    if config.REGISTRY_DOMAIN is not None:
        image = f"{config.REGISTRY_DOMAIN}/project/{image}"
    return image


type BuildMap = defaultdict[str, dict[BuildConfig, BuildArtifacts]]


type POVRun = Tuple[BuildConfig, process.ProcRes]
type POVRunReturn = Optional[POVRun]
@requireable
async def run_pov(
    builds: list[BuildArtifacts],
    base_builds: Optional[list[BuildArtifacts]],
    harness_name: str,
    pov_dat: bytes,
    timeout: float = DEFAULT_POV_TIMEOUT,
) -> Result[POVRunReturn]:
    # build before acquiring any docker scope
    try:
        async with docker.scope(group=docker.DockerGroup.Misc, timeout=DEFAULT_POV_TIMEOUT*2) as scope:
            match await run_povs_post_acquire(builds, base_builds, scope, [Ok((harness_name, pov_dat))], timeout=timeout):
                case Ok(r):
                    return r[0]
                case Err() as e:
                    return e
    except TimeoutError:
        return Err(CRSError("Timeout while trying to start POV test, please try again."))

async def run_pov_first_crash(
    runners: list[tuple[BuildArtifacts, docker.DockerRun]],
    pov_data: bytes,
    harness_name: str,
    timeout: float = DEFAULT_POV_TIMEOUT,
) -> Result[POVRunReturn]:
    @requireable
    async def run_pov_inner(artifact: BuildArtifacts, runner: docker.DockerRun) -> Result[Project.POVRun]:
        try:
            async with asyncio.timeout(timeout):
                reader = require(await artifact.run_pov_inside(runner, pov_data, harness_name))
                return Ok((artifact.build_config, await reader.communicate()))
        except TimeoutError:
            return Err(CRSError("pov test timed out"))

    async with asyncio.TaskGroup() as tg:
        first_task: Optional[asyncio.Task[Result[Project.POVRun]]] = None
        tasks: set[asyncio.Task[Result[Project.POVRun]]] = set()
        try:
            for artifact, runner in runners:
                t = tg.create_task(run_pov_inner(artifact, runner), name=f"run_pov_inner(): project={artifact.project_name} harness={harness_name}")
                if first_task is None:
                    first_task = t
                tasks.add(t)
            assert first_task

            # allow 5 seconds for the first build config to finish before trying the others
            done, _ = await asyncio.wait([first_task], timeout=min(5.0, timeout))
            if done:
                task = done.pop()
                match await task:
                    case Ok((build_conf, result)):
                        if result.returncode != 0:
                            return Ok((build_conf, result))
                    case _:
                        pass
                tasks.remove(task)
            # our first config didn't return in 5s, wait for whatever is first
            while tasks:
                done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    match await task:
                        case Ok((build_conf, result)):
                            if result.returncode != 0:
                                return Ok((build_conf, result))
                        case _:
                            pass

            # no crashes
            return Ok(None)
        finally:
            # cancel anything still running
            for task in tasks:
                _ = task.cancel()

@requireable
async def run_povs_post_acquire(
    builds: list[BuildArtifacts],
    base_builds: Optional[list[BuildArtifacts]],
    scope: docker.DockerScope,
    pov_datas: Sequence[Result[tuple[str|Harness, bytes]]],
    timeout: float = DEFAULT_POV_TIMEOUT,
) -> Result[list[Result[POVRunReturn]]]:
    # use this to run once our "slow" acquire ops are done, in case we are collecting
    # from a batch
    if not pov_datas:
        return Ok([])
    if not builds:
        return Err(CRSError("no builds supplied"))

    global_timeout = timeout * len(pov_datas) + (3 if len(pov_datas) == 1 else 0)

    try:
        res: list[Result[Project.POVRunReturn]] = []
        runners: list[tuple[BuildArtifacts, docker.DockerRun]] = []
        async with (
            asyncio.timeout(global_timeout), # noqa: ASYNC912; we are guaranteed to call await because the lists are nonempty
            contextlib.AsyncExitStack() as stack
        ):
            for build in builds:
                runner = await stack.enter_async_context(build.run(timeout=global_timeout, scope=scope))
                runners.append( (build, runner) )
            for pov_data_entry in pov_datas:
                match pov_data_entry:
                    case Ok(((str() as harness_name) | Harness(name=harness_name), pov_data)):
                        res.append(await run_pov_first_crash(runners, pov_data, harness_name, timeout))
                    case Err() as e:
                        res.append(e)
        if base_builds:
            async with (
                asyncio.timeout(global_timeout), # noqa: ASYNC912; we are guaranteed to call await because the lists are nonempty
                contextlib.AsyncExitStack() as stack
            ):
                for build in base_builds:
                    runner = await stack.enter_async_context(build.run(timeout=global_timeout, scope=scope))
                    runners.append( (build, runner) )
                for idx, (first_res, pov_data_entry) in enumerate(zip(res, pov_datas)):
                    # no need to re-run for an error or non-crash
                    if first_res.is_err() or first_res == Ok(None):
                        continue
                    match pov_data_entry:
                        case Ok(((str() as harness_name) | Harness(name=harness_name), pov_data)):
                            match await run_pov_first_crash(runners, pov_data, harness_name, timeout):
                                case Ok(crash_res):
                                    # if we got a crash_res on base; rewrite the entry
                                    if crash_res is not None and crash_res[1].returncode != 0:
                                        res[idx] = Err(CRSError("crash reproduces before the diff was applied"))
                                case Err():
                                    pass
                        case Err() as e:
                            # already handled in first loop
                            pass
        return Ok(res)
    except TimeoutError:
        return Err(CRSError("timed out"))


# note: must always accessed from a single run-loop
build_locks: defaultdict[Tuple[str, BuildConfig], asyncio.Lock] = defaultdict(asyncio.Lock)

class Project:
    project_dir: Path
    info: ProjectInfo
    data_dir: Path
    vfs: EditableOverlayFS
    searcher: Searcher
    harnesses: Optional[list[Harness]]
    editor: Editor
    builds: BuildMap
    ossfuzz_hash: str
    _working_dir: Optional[str]

    def __init__(
        self,
        project_dir: Path,
        data_dir: Path,
        vfs: EditableOverlayFS,
        info: ProjectInfo,
        ossfuzz_hash: str,
        harnesses: Optional[list[Harness]] = None,
        builds: Optional[BuildMap] = None,
        workdir: Optional[str] = None,
        gtags: Optional[GTagDB] = None
    ):
        self.project_dir = project_dir
        self.info = info or ProjectInfo(**yaml.safe_load(open(project_dir / PROJECT_YAML_FILE)))
        self.data_dir = data_dir
        self.vfs = vfs
        self.editor = Editor(vfs)
        self.searcher = Searcher(self, self.editor, gtags=gtags)
        self.harnesses = harnesses
        self.builds = builds or defaultdict(dict)
        self.build_image = _build_image_name(project_dir.name, ossfuzz_hash)
        self.ossfuzz_hash = ossfuzz_hash
        self._working_dir = workdir

    @classmethod
    async def from_dir[T: Project](cls: Type[T], project_dir: str | Path, *, ossfuzz_hash: str) -> T:
        project_dir = Path(os.path.normpath(project_dir))
        build_image = _build_image_name(project_dir.name, ossfuzz_hash)
        data_dir, info, workdir = await _init_project_data(project_dir, build_image, ossfuzz_hash)
        vfs = EditableOverlayFS(await TarFS.fsopen(data_dir / "src.tar"))
        return cls(project_dir, data_dir, vfs, info, ossfuzz_hash, workdir=workdir)

    async def runner_image(self) -> Result[str]:
        return Ok(RUNNER_IMAGE)

    async def build_key(self, conf: BuildConfig) -> str:
        return f"{self.name}_{str(conf)}_{await self.edit_state()}"

    async def get_build_tar(self, conf: BuildConfig) -> Path:
        return self.data_dir / f"{await self.build_key(conf)}.tar"

    async def get_joern_tar(self) -> Path:
        return self.data_dir / f"cpg_{await self.edit_state()}.bin.tar"

    async def get_joern_callgraph(self) -> Path:
        return self.data_dir / f"callgraph_{await self.edit_state()}.json"

    async def harness_info(self) -> Path:
        return self.data_dir / f"harness_info_{await self.edit_state()}.json"

    @alru_cache(maxsize=128)
    async def get_build_vfs(self, conf: BuildConfig) -> VFS:
        return await TarFS.fsopen(await self.get_build_tar(conf))

    @async_once
    async def get_bear_tar(self) -> Path:
        return self.data_dir / f"bear_src_post_compile_{await self.parent_edit_state()}.tar"

    @async_once
    async def get_bear_vfs(self) -> TarFS:
        return await TarFS.fsopen(await self.get_bear_tar())

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def init_harness_info(self) -> Result[list[Harness]]:
        if self.harnesses is not None:
            return Ok(self.harnesses)
        artifacts = require(await self.build_all())
        logger.info(f"locating harnesses for {self.project_dir.as_posix()}")
        harnesses: list[Harness] = []

        artifacts = [a for a in artifacts if a.build_config == self.info.default_build_config][0]
        mounts = {
            config.CRS_HARNESS_MATCH: "/opt/harness_match.py",
        }

        harness_info_path = await self.harness_info()
        if await harness_info_path.exists():
            logger.info(f"using cached harness info: {harness_info_path}")
            harness_info_json = await harness_info_path.read_bytes()
        else:
            async with docker.run(SANDBOX_IMAGE_NAME, mounts=mounts, timeout=DEFAULT_INIT_TIMEOUT) as run:
                require(await docker.vwrite_layers(run, "/out", await artifacts.build_vfs.layers()))
                require(await docker.vwrite_layers(run, "/src", await self.vfs.parent.layers()))

                proc = await run.exec(
                    "python3", "/opt/harness_match.py", self.info.language,
                    stdout=PIPE, stderr=PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    return Err(CRSError("init_harness_info failed: " + stderr[:config.MAX_ERROR_OUTPUT].decode(errors="replace")))
                harness_info_json = stdout
                async with aio.tmpfile(dir=harness_info_path.parent) as f:
                    _ = await f.path.write_bytes(harness_info_json)
                    await f.path.replace(harness_info_path)

        j = await asyncio.to_thread(orjson.loads, harness_info_json)
        for path, matches in j.items():
            basename = os.path.basename(path)
            if len(matches) == 1:
                source = matches.pop()
                if await artifacts.build_vfs.is_file(f"{basename}.options"):
                    options = (await artifacts.build_vfs.read(f"{basename}.options")).decode(errors="replace")
                else:
                    options = ""
                fuzz_function = None
                if await self.vfs.is_file(source):
                    source_content = (await self.vfs.read(source))
                    if self.info.language == "jvm":
                        targets = {"fuzzerTestOneInput", "FuzzTest"}
                    else:
                        targets = {"LLVMFuzzerTestOneInput", "DEFINE_PROTO_FUZZER"}
                    for target in targets:
                        if target.encode() in source_content:
                            fuzz_function = target
                            break
                harnesses.append(Harness(name=basename, type=HarnessType.LIBFUZZER, source=source, options=options, harness_func=fuzz_function))
            else:
                logger.error(f"no obvious match for {basename}: {matches}")

        harnesses.sort(key=lambda h: h.name)
        self.harnesses = harnesses

        with config.telem_tracer.start_as_current_span(
            "init_harness_info",
            attributes={"crs.debug.target.num_harnesses": len(harnesses)},
            record_exception=False
        ) as span:
            for i, harness in enumerate(harnesses):
                span.add_event(
                    f"matched harness {i}",
                    attributes={
                        "crs.action.target.harness": harness.name,
                        "crs.debug.target.harness.source": harness.source,
                    }
                )
        return Ok(harnesses)

    @alru_cache(maxsize=None)
    async def read_harness_func(self, harness: Harness) -> Optional[str]:
        if harness.harness_func is not None:
            match await self.searcher.read_definition(harness.harness_func, harness.source):
                case Ok(file_data):
                    return file_data["contents"]
                case _:
                    pass

    def __getstate__(self) -> Any:
        return self.project_dir, self.ossfuzz_hash, self.data_dir, self.vfs

    def __setstate__(self, state: Any):
        match state:
            case (Path() as project_dir, ossfuzz_hash, Path() as data_dir, EditableOverlayFS() as vfs): pass
            case _: raise Exception("unexpected state for Project")
        import pathlib
        project_yaml = pathlib.Path(project_dir / PROJECT_YAML_FILE)
        info = ProjectInfo(**yaml.safe_load(project_yaml.read_bytes()))
        self.__init__(project_dir, data_dir, vfs, info, ossfuzz_hash)

    @property
    def name(self) -> str:
        return self.project_dir.name

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def get_working_dir(self) -> Result[str]:
        if (workdir := self._working_dir) is not None:
            return Ok(workdir)
        async with docker.scope(timeout=DEFAULT_INIT_TIMEOUT) as scope:
            return Ok(require(await docker.get_image_workdir(scope, self.build_image)))

    async def parent_edit_state(self) -> str:
        return (await self.vfs.parent.hash()).hex()

    async def edit_state(self) -> str:
        return (await self.vfs.hash()).hex()

    @requireable
    async def _build(
        self,
        build_config: BuildConfig,
        mounts: dict[Path, str] = {},
        timeout: float = DEFAULT_BUILD_TIMEOUT,
        capture_output: bool = False,
        using_bear: bool = False,
        scope: Optional[docker.DockerScope] = None,
    ) -> Result[BuildArtifacts]:
        with config.telem_tracer.start_as_current_span("build", attributes={"crs.action.category": "building"}, record_exception=False) as span:
            span.set_attributes({
                "crs.debug.build.sanitizer": build_config.SANITIZER,
                "crs.debug.build.language": build_config.FUZZING_LANGUAGE,
                "crs.debug.build.engine": build_config.FUZZING_ENGINE,
                "crs.debug.build.using_bear": using_bear,
            })
            bear_tar = await self.get_bear_tar()
            build_tar = await self.get_build_tar(build_config)
            # build is cached, just return it
            if await build_tar.exists() and (await bear_tar.exists() or not using_bear):
                logger.info(f"Using cached build at {build_tar}")
                span.add_event("build cache hit")
                return Ok(BuildArtifacts(self.name, build_config, await self.get_build_vfs(build_config)))
            logger.info(f"Building project {self.project_dir.as_posix()} to {build_tar}")

            if capture_output:
                stdio_fd = asyncio.subprocess.PIPE
            elif SILENCE_BUILDS:
                stdio_fd = asyncio.subprocess.DEVNULL
            else:
                stdio_fd = None

            # wrap ALL compiles with theori_compile.sh to allow commands to run before build.sh
            mounts[config.THEORI_COMPILE] = "/usr/local/bin/theori_compile.sh"
            compile_commands = ["theori_compile.sh"]
            copies: list[tuple[str, Path, list[str]]] = []

            if using_bear:
                if self.info.language in {"c", "c++"}:
                    mounts[config.BEAR_PATH / "usr/lib/x86_64-linux-gnu/bear/"] = "/usr/lib/x86_64-linux-gnu/bear/"
                    mounts[config.BEAR_PATH / "usr/bin/bear"] = "/opt/bear"
                    compile_commands = ["python3", "/opt/bear", "-o", "/src/compile_commands.json","theori_compile.sh"]
                    include_dirs = ["compile_commands.json"]
                    workdir = await self.get_working_dir()
                    if workdir.is_ok():
                        include_dirs.append(Path(workdir.unwrap()).relative_to("/src/").as_posix())
                    include_dirs.append(Path(self.info.main_repo).stem)
                copies.append(("/src", bear_tar, DEFAULT_FUZZER_DIRS))

            reader = process.Reader()
            try:
                async with docker.run(self.build_image, env=build_config.to_dict(), mounts=mounts, timeout=timeout, scope=scope) as run:
                    # materialize /src vfs in container
                    vfs = self.vfs.parent if using_bear else self.vfs
                    require(await docker.vwrite_layers(run, "/src", await vfs.layers()))

                    proc = await run.exec(*compile_commands, stdout=stdio_fd, stderr=stdio_fd)
                    reader = process.Reader(proc)
                    res = await reader.communicate()

                    # if the build succeeds, copy it to {build_tar}, otherwise return the failure
                    if res.returncode != 0:
                        span.add_event("compile command failed")
                        return Err(BuildError(res.output))

                    # get a list of plausible looking harness files, exclude anything corpus zip looking
                    out_files = await docker.vls(run, "/out")
                    corpus_zips: list[str] = []
                    for f in out_files:
                        if f.endswith("_seed_corpus.zip"):
                            if f.removesuffix("_seed_corpus.zip") in out_files: # looks like a corpus
                                corpus_zips.append(f)
                    copies.append( ("/out", build_tar, corpus_zips) )

                    for path, tar, excludes in copies:
                        exclude_arg = [arg for ex in excludes for arg in ["--exclude", ex]]
                        async with aio.tmpfile(dir=self.data_dir, prefix=f"build-{tar.name}.tmp") as tf:
                            proc = await run.exec(
                                "tar", "cf", "-", *exclude_arg, "--transform", r"s/^\.\///", "-C", path, ".",
                                stdout=tf,
                            )
                            if await proc.wait() != 0:
                                span.add_event("build artifacts copy failed")
                                return Err(CRSError(f"could not copy /out to {tar!r}"))
                            await tf.path.replace(tar)
            except TimeoutError:
                span.add_event("build timed out")
                return Err(CRSError("Build timed out"))
            span.add_event("build success")
            assert await build_tar.exists()
            return Ok(BuildArtifacts(self.name, build_config, await TarFS.fsopen(build_tar)))

    async def build_default(self) -> Result[BuildArtifacts]:
        return await self.build(self.info.default_build_config)

    async def build(
        self,
        build_config: BuildConfig,
        mounts: dict[Path, str] = {},
        timeout: float = DEFAULT_BUILD_TIMEOUT,
        capture_output: bool = False,
        scope: Optional[docker.DockerScope] = None,
    ) -> Result[BuildArtifacts]:
        state = await self.edit_state()
        if (res := self.builds[state].get(build_config)) is not None:
            return Ok(res)
        async with build_locks[(state, build_config)]:
            # TODO: can we reliably mix the mounts into the dict keys below?
            if (res := self.builds[state].get(build_config)) is None:
                match await self._build(build_config, mounts, timeout, capture_output, scope=scope):
                    case Ok(res):
                        self.builds[state][build_config] = res
                    case Err() as e:
                        return e
            return Ok(res)

    async def build_bear_tar(
        self,
        mounts: dict[Path, str] = {},
        timeout: float = DEFAULT_BUILD_TIMEOUT,
        capture_output: bool = False
    ) -> Optional[Path]:
        if self.info.language not in {"c", "c++"}:
            return None
        build_config = self.info.default_build_config
        state = await self.edit_state()
        if await (bear_tar := await self.get_bear_tar()).exists():
            return bear_tar
        async with build_locks[(state, build_config)]:
            if await bear_tar.exists():
                return bear_tar
            # try using bear on the default build
            match await self._build(build_config, mounts, timeout, capture_output, using_bear=True):
                case Ok(res):
                    self.builds[state][build_config] = res # might as well cache the build artifacts as well
                    return bear_tar
                case Err(error):
                    logger.warning(f"error during bear build: {error}")
                    return None

    async def build_all(self, timeout: float = DEFAULT_BUILD_TIMEOUT, capture_output: bool = False) -> Result[list[BuildArtifacts]]:
        return collect(
            await asyncio.gather(*[
                self.build(conf, timeout=timeout, capture_output=capture_output) for conf in self.info.build_configs
            ])
        )

    type POVRun = Tuple[BuildConfig, process.ProcRes]
    type POVRunReturn = Optional[POVRun]
    @requireable
    async def run_pov(
        self,
        harness_name: str,
        pov_dat: bytes,
        timeout: float = DEFAULT_POV_TIMEOUT,
    ) -> Result[POVRunReturn]:
        # build before acquiring any docker scope
        builds = require(await self.build_all())
        return await run_pov(builds, None, harness_name, pov_dat, timeout)

    def check_harness(self, harness_num: int) -> Result[Harness]:
        assert self.harnesses is not None and len(self.harnesses) > 0, "harnesses not initialized"
        if harness_num < 0 or harness_num >= len(self.harnesses):
            if len(self.harnesses) == 1:
                suggestion = "harness id 0"
            else:
                suggestion = f"a harness id between 0 and {len(self.harnesses)-1} (inclusive)"
            return Err(CRSError(
                f"harness_num out of range. There are only {len(self.harnesses)} harnesses",
                {"suggestion": f"Please try again with {suggestion}"}
            ))
        return Ok(self.harnesses[harness_num])

    @contextlib.asynccontextmanager
    async def run_bear_docker(self, mounts: Optional[dict[Path, str]] = None, timeout: int = DEFAULT_BUILD_TIMEOUT) -> AsyncIterator[Result[docker.DockerRun]]:
        if (await self.build_bear_tar()) is None:
            yield Err(CRSError("no bear build available"))
            return

        build_config = self.info.default_build_config
        vfs_mounts = [
            (await self.get_bear_vfs(), "/src"),
            (await self.get_build_vfs(build_config), "/out")
        ]

        async with docker.run(self.build_image, mounts=mounts, env=build_config.model_dump(), timeout=timeout) as run:
            for vfs, dst in vfs_mounts:
                match await docker.vwrite_layers(run, dst, await vfs.layers()):
                    case Ok(_): pass
                    case Err() as e:
                        yield e
                        return
            yield Ok(run)

    @requireable
    async def build_pov(self, input_python: str) -> Result[bytes]:
        """
        Attempt to run python code and capture the input binary it produces.
        """
        python_res = require(await run_python(input_python))
        if not python_res.success:
            return Err(CRSError(
                "ERROR: the provided python failed to run",
                extra={
                    "stdout": python_res.stdout,
                    "stderr": python_res.stderr,
                }
            ))

        if len(python_res.files) == 0:
            return Err(CRSError(
                "ERROR: the provided python code did not produce a file named input.bin",
                extra={
                    "stdout": python_res.stdout,
                    "stderr": python_res.stderr,
                }
            ))

        # don't bother checking the file name, just use it
        if len(python_res.files) == 1:
            contents, = python_res.files.values()
        elif (contents := python_res.files.get("input.bin")) is None:
            return Err(CRSError(
                "ERROR: the provided python code did not produce a file named input.bin",
                extra={
                    "stdout": python_res.stdout,
                    "stderr": python_res.stderr,
                    "files_created": list(python_res.files),
                }
            ))
        return contents

    class PrePoc(BaseModel):
        harness: str
        contents: bytes

    @requireable
    async def _pre_pov(self, harness_num: int, pov_python: str) -> Result[tuple[bytes, Harness]]:
        """
        Sanity checks harness_num and pov_python for running povs
        """
        # step 0: make sure the harness_num is valid
        harness = require(self.check_harness(harness_num))

        # step 1: run the python code
        contents = require(await self.build_pov(pov_python))
        return Ok((contents, harness))

    @requireable
    async def test_pov(self, harness_num: int, pov_python: str) -> Result[CrashResult]:
        """
        Uses the given Python PoV script to generate a bytestring which is then
        passed to the test harness. The Python code MUST produce a file named
        "input.bin" in the current working directory when run. This will be the PoV
        input blob. Note the python code will be run in a fresh interpreter,
        so be sure to define or import everything you need.
        <important>
        Use this tool when you have some PoV python you think may trigger a bug.
        </important>

        Parameters
        ----------
        harness_num : int
            The (0 indexed) harness against which to test

        pov_python : str
            The python code we will run. This will be executed with no input, and
            must produce a file named "input.bin". It MUST NOT try to run the harness
            itself, ONLY write a file with the data to send to the harness. It will
            be run in a new interpreter and must define or import everything referenced.

        Returns
        -------
        dict
            dictionary representing errors, success, failures, etc for feedback upstream
        """
        contents, harness = require(await self._pre_pov(harness_num, pov_python))
        return await self.test_pov_contents(harness, contents)

    def parse_crash_contents(self, conf: BuildConfig, contents: bytes, res: process.ProcRes):
        output_simplified = "\n".join(x for x in res.output.split("\n") if not x.startswith("INFO:"))
        stack = ""
        # for multi-threaded programs, multiple dedup tokens may be printed -_-
        dedup = "==".join(
            line.removeprefix(b"DEDUP_TOKEN: ").decode(errors="replace").replace("/", "|")
            for line in res.stderr.splitlines()
            if line.startswith(b"DEDUP_TOKEN: ")
        )
        if self.info.language == 'jvm':
            state = 0
            for line in output_simplified.splitlines(keepends=True):
                if state == 0 and line.startswith("== Java Exception:"):
                    stack += line
                    state = 1
                elif state == 1 and (line.startswith("==") or not line):
                    break
                elif state == 1:
                    stack += line
            if not stack: # check for timeout format
                state = 0
                for line in output_simplified.splitlines(keepends=True):
                    if state == 0 and re.match(r"==\d+==", line):
                        stack += line
                        state = 1
                    elif state == 1 and (line.startswith("SUMMARY") or line.startswith("Garbage collector stats")):
                        break
                    elif state == 1:
                        stack += line
        else:
            output = res.stderr.decode(errors="replace")
            # first try our custom stack printer
            stack = "\n".join(
                line.removeprefix("Stack Frame ") for line in output.splitlines()
                if re.match(r"Stack Frame #\d+ in", line)
            )
            # if there's nothing, try the more generic stack parser
            if not stack and (match := re.findall(r"(^ *#\d+ .*$)+", output, re.MULTILINE)):
                # filter out absolute addresses if we can
                # '#5 0x5f16b941dee3 in cmdline_option_value shell.c' -> '#5 in cmdline_option_value shell.c'
                stack = "\n".join(re.sub(r' *(#\d+ )(?:0x[0-9a-f]+ )?(.*)',r'\1\2', m) for m in match)
            # getting desparate, did we get the traceback with =={pid}==? if so, anything after that is stack-y
            if not stack and (crash_header := re.search(r"==\d+==", output)):
                stack = "\n".join(output[crash_header.end():].splitlines()[1:])
            # still no?? let's just use whatever it printed?
            if not stack:
                stack = output
        if not dedup:
            dedup = sha256(stack.encode()).hexdigest()
        return CrashResult(config=conf, input=contents, output=output_simplified, dedup=dedup, stack=stack)

    @requireable
    async def test_pov_contents(self, harness: Harness, contents: bytes) -> Result[CrashResult]:
        """
        Internal function for pov testing
        """
        pov_res = require(await self.run_pov(harness.name, contents))

        if pov_res is None:
            return Err(CRSError("the POV did not crash on any build config"))

        return Ok(self.parse_crash_contents(pov_res[0], contents, pov_res[1]))


    def new_fork(self, vfs: Optional[VFS] = None, preserve_gtags: bool = True) -> 'Project':
        vfs = EditableOverlayFS(vfs) if vfs else self.vfs.fork()
        gtags = self.searcher.gtags if preserve_gtags else None
        return Project(self.project_dir, self.data_dir, vfs, self.info, self.ossfuzz_hash, self.harnesses, self.builds, workdir=self._working_dir, gtags=gtags)

    @requireable
    async def fork_with_source(self, source_vfs: VFS, repo_name: str) -> Result['Project']:
        repo_path = require(await self.repo_path())
        fork = self.new_fork(vfs=MountFS(self.vfs.parent, repo_path.as_posix(), source_vfs, repo_name), preserve_gtags=False)
        return Ok(fork)

    @async_once
    @requireable
    async def repo_path(self):
        workdir = Path(require(await self.get_working_dir()))
        return Ok(workdir.relative_to("/src"))

    @requireable
    async def run_tests(self, timeout: float = DEFAULT_BUILD_TIMEOUT) -> Result[None]:
        local_test_script = self.project_dir / "test.sh"
        if not await local_test_script.exists():
            return Err(NoTests(f"{local_test_script} does not exist"))
        test_script_contents = await local_test_script.read_bytes()
        try:
            async with docker.run(self.build_image, timeout) as run:
                require(await docker.vwrite_layers(run, "/src", await self.vfs.layers()))
                require(await docker.vwrite(run, {"/src/test.sh": test_script_contents}))
                logger.info(f"running functionality tests for project: {self.name}")
                proc = await run.exec("chmod", "+x", "/src/test.sh")
                if await proc.wait() != 0:
                    return Err(CRSError("could not chmod test.sh"))
                proc = await run.exec("/src/test.sh", stdout=PIPE, stderr=STDOUT)
                stdout, _ = await proc.communicate()
                output = stdout.decode(errors='replace')
                if await proc.wait() != 0:
                    return Err(TestFailure(f"Tests failed to run", extra={"output": output}))
                logger.info(f"functionality tests for project '{self.name}' passed")
                return Ok(None)
        except TimeoutError:
            return Err(CRSError("tests timed out"))

@dataclass(eq=False)
class Task():
    task_id: uuid.UUID
    deadline: int
    project: Project
    coverage: 'CoverageAnalyzer'
    debugger: 'Debugger'
    metadata: dict[str, str]
    deadline_datetime: datetime = field(init=False)

    def __post_init__(self):
        self.deadline_datetime = datetime.fromtimestamp(self.deadline / 1000, tz=timezone.utc)

    @alru_cache(maxsize=100)
    async def tar_fs_from_path(self, tar: Path):
        return await TarFS.fsopen(tar)

    @requireable
    async def test_pov(self, harness_num: int, pov_python: str) -> Result[CrashResult]:
        return await self.project.test_pov(harness_num, pov_python)

    async def test_pov_contents(self, harness: Harness, contents: bytes) -> Result[CrashResult]:
        return await self.project.test_pov_contents(harness, contents)

@dataclass(eq=False)
class DeltaTask(Task):
    base: Project
    diff: str

    @requireable
    async def test_pov(self, harness_num: int, pov_python: str) -> Result[CrashResult]:
        harness = require(self.project.check_harness(harness_num))
        contents = require(await self.project.build_pov(pov_python))
        return await self.test_pov_contents(harness, contents)

    async def test_pov_contents(self, harness: Harness, contents: bytes) -> Result[CrashResult]:
        match await self.project.test_pov_contents(harness, contents):
            case Err() as e:
                return e
            case Ok(res):
                match await self.base.test_pov_contents(harness, contents):
                    case Err():
                        return Ok(res)
                    case Ok():
                        return Err(CRSError(
                            "That POV triggers a crash, but it also crashes BEFORE the targetted commit. "
                            "That means it is NOT eligible for scoring. Please check if there is another "
                            "bug that you can target that was introduced in the diff for this commit!"
                        ))

    @async_once
    async def pruned_diff(self, rawdiff: bool=False):
        ignore_paths = set([
            path for path in diff_utils.iter_post_paths(self.diff)
                if Path(path).suffix.lower() in SOURCE_CODE_EXTENSIONS
                and not await self.project.searcher.compiler_might_use_path(path)
        ])
        
        if rawdiff:
            pruned = self.diff
        else:
            pruned = diff_utils.filter_diff(
                self.diff,
                lambda section, prev, post: None if prev in ignore_paths else section
            )

        # if the diff is too big, we can't show the entire thing to our agents
        # FIXME: intelligently split diff into reasonable chunks
        trimmed = trim_tool_output(pruned, ratio=1)
        if len(trimmed) < len(pruned):
            # for now, just log an error
            logger.error("Diff was too big and had to be trimmed")
        return trimmed
