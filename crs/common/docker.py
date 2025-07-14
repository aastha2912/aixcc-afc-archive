from asyncio.subprocess import DEVNULL, PIPE, Process
from crs.common.aio import Path
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Collection, Optional, Sequence, Mapping, Iterable, cast
from urllib.parse import urlparse
import asyncio
import contextlib
import enum
import io
import ipaddress
import math
import os
import random
import re
import tarfile

from crs.config import metrics, telem_tracer, REGISTRY_DOMAIN
from crs.common import aio, process
from crs.common.shield import shield_and_wait
from crs.common.azure import ensure_acr_login
from crs.common.types import Result, Ok, Err, CRSError
from crs.common.utils import requireable, require, finalize

from crs_rust import logger

docker_group_waiters = metrics.create_counter("docker_group_waiters")

CONTAINER_SPAWN_TIMEOUT = 300

class DockerGroup(enum.Enum):
    Build = "build"
    Fuzz = "fuzz"
    Misc = "misc"

class DockerScope:
    manager: "DockerManager"
    host: "DockerHost"
    group: Optional[DockerGroup]
    timeout: Optional[float]
    scope: process.ProcessScope
    task: Optional[asyncio.Task[Any]]

    def __init__(self, manager: "DockerManager", host: "DockerHost", task: Optional[asyncio.Task[Any]]=None, group: Optional[DockerGroup]=None, timeout: Optional[float]=None):
        self.manager = manager
        self.host = host
        self.group = group
        self.timeout = timeout
        self.task = task

    def __repr__(self) -> str:
        scope = getattr(self, "scope", None)
        return f"DockerScope(host={self.host!r}, group={self.group!r}, {scope=})"

    @property
    def env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.host.ip is not None:
            env["DOCKER_HOST"] = self.host.ip
        return env

    async def exec(self, cmd: str, *args: str, **kwargs: Any) -> Process:
        env: dict[str, Any] = kwargs.pop("env", None) or os.environ.copy()
        env.update(self.env)
        return await self.scope.exec(cmd, *args, env=env, **kwargs)

    @contextlib.asynccontextmanager
    async def exec_scoped(self, cmd: str, *args: str, timeout: Optional[float] = None, **kwargs: Any) -> AsyncIterator[Process]:
        env: dict[str, Any] = kwargs.pop("env", None) or os.environ.copy()
        env.update(self.env)
        async with process.scope(timeout=timeout) as scope:
            yield await scope.exec(cmd, *args, env=env, **kwargs)

@dataclass
class DockerHost:
    ip: Optional[str]
    group: DockerGroup
    cores: int
    slots: dict[DockerScope, int] = field(default_factory=dict[DockerScope, int])

    def has_slots(self, cores: int = 1) -> bool:
        if self.ip is None:
            return True
        if self.cores == 0 or self.group == DockerGroup.Build:
            return not self.slots
        return sum(self.slots.values()) + cores <= self.cores

local_host = DockerHost(ip=None, group=DockerGroup.Misc, cores=0)

class DockerManager:
    groups: dict[DockerGroup, list[DockerHost]]
    cond: asyncio.Condition

    def __init__(self):
        build_count = int(os.environ.get("CRS_BUILDER_COUNT") or 0)
        fuzz_count = int(os.environ.get("CRS_FUZZER_COUNT") or 0)
        build_cores = int(os.environ.get("CRS_BUILDER_CORES") or 0)
        fuzz_cores = int(os.environ.get("CRS_FUZZER_CORES") or 0)

        build_ips = [f"10.0.2.{n + 10}" for n in range(build_count)]
        fuzz_ips  = [f"10.0.3.{n + 10}" for n in range(fuzz_count)]
        misc_ips: list[str] = []
        # steal ceil(10%) of the build hosts for misc if we have >1 host
        if len(build_ips) > 1:
            n_misc = math.ceil(len(build_ips) * 0.1)
            misc_ips += build_ips[:n_misc]
            build_ips = build_ips[n_misc:]

        group_ips = {
            DockerGroup.Build: build_ips,
            DockerGroup.Fuzz: fuzz_ips,
            DockerGroup.Misc: misc_ips,
        }
        group_cores = {
            DockerGroup.Build: build_cores,
            DockerGroup.Fuzz:  fuzz_cores,
            DockerGroup.Misc:  build_cores,
        }
        self.groups = {group: [DockerHost(ip=ip, group=group, cores=group_cores[group]) for ip in ips]
                       for group, ips in group_ips.items()}
        self.cond = asyncio.Condition()

    @contextlib.asynccontextmanager
    async def scope(
        self, *,
        group: DockerGroup=DockerGroup.Build,
        cores: int = 1,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[DockerScope]:
        dscope = await self.alloc(group=group, cores=cores, timeout=timeout)
        async with process.scope(timeout=dscope.timeout) as pscope:
            dscope.scope = pscope
            logger.debug(f"[DockerScope] enter: {dscope}")
            async with finalize(self.free(dscope)):
                yield dscope

    @telem_tracer.start_as_current_span("docker_alloc", record_exception=False)
    async def alloc(
        self, *,
        group: DockerGroup=DockerGroup.Build,
        cores: int = 1,
        timeout: Optional[float] = None,
    ) -> DockerScope:
        task = asyncio.current_task()
        hosts = self.groups[group]
        if not hosts:
            scope = DockerScope(self, host=local_host, task=task, group=group, timeout=timeout)
            local_host.slots[scope] = cores
            return scope
        hosts = hosts.copy()
        random.shuffle(hosts)

        assert cores <= hosts[0].cores, "request for more cores than a machine has, will block forever!"

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout if timeout is not None else None
        async with asyncio.timeout_at(deadline):
            try:
                docker_group_waiters.add(1, {"group": group.value})
                async with self.cond:
                    while True:
                        for host in hosts:
                            if host.has_slots(cores=cores):
                                break
                        else:
                            logger.debug(f"DockerManager.alloc({group=}) waiting")
                            _ = await self.cond.wait()
                            continue
                        break

                    if deadline is not None:
                        timeout = max(0.0, deadline - loop.time())

                    scope = DockerScope(self, host=host, task=task, group=group, timeout=timeout)
                    host.slots[scope] = cores
                    return scope
            finally:
                docker_group_waiters.add(-1, {"group": group.value})

    async def free(self, scope: DockerScope) -> None:
        logger.debug(f"[DockerScope] free: {scope}")
        host = scope.host
        async with self.cond:
            _ = host.slots.pop(scope, None)
            self.cond.notify_all()

manager = DockerManager()


# expects to be run inside an asyncio timeout
async def watch_file(path: Path):
    while True:
        try:
            st = os.stat(path)
            if st.st_size > 0:
                break
        except FileNotFoundError:
            pass
        await asyncio.sleep(0.050)

@dataclass(slots=True, frozen=True)
class HostPort:
    host: str
    port: int

    def __str__(self):
        try:
            ip = ipaddress.ip_address(self.host)
        except ValueError:
            return f"{self.host}:{self.port}"
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{ip}]:{self.port}"
        return f"{ip}:{self.port}"

@dataclass(slots=True)
class DockerRun:
    scope: DockerScope
    cid: str
    port_map: dict[int, HostPort]

    async def exec(self, *cmd: str, docker_args: Optional[Sequence[str]] = None, **kwargs: Any) -> Process:
        docker_args = list(docker_args or ())
        if kwargs.get("stdin") not in (None, DEVNULL):
            docker_args.append("-i")
        return await self.scope.exec("docker", "exec", *docker_args, self.cid, *cmd, **kwargs)

    @contextlib.asynccontextmanager
    async def exec_scoped(self, *cmd: str, docker_args: Optional[Sequence[str]] = None, timeout: Optional[float] = None, **kwargs: Any) -> AsyncIterator[Process]:
        docker_args = list(docker_args or ())
        if kwargs.get("stdin") not in (None, DEVNULL):
            docker_args.append("-i")
        async with self.scope.exec_scoped("docker", "exec", *docker_args, self.cid, *cmd, timeout=timeout, **kwargs) as proc:
            yield proc


def parse_docker_host(host: str) -> str:
    if "/" in host:
        host = urlparse(host).netloc
    return host.split(":")[0].strip("[]")

scope = manager.scope

@contextlib.asynccontextmanager
async def run(
    image: str,
    timeout: Optional[float],
    mounts: Optional[Mapping[Path, str | Path]] = None,
    env: Optional[Mapping[str, str]] = None,
    ports: Optional[Sequence[int]] = None,
    group: DockerGroup = DockerGroup.Build,
    scope: Optional[DockerScope] = None,
    cores: int = 1
) -> AsyncIterator[DockerRun]:
    logger.info(f"docker.run({image=}, {timeout=})")

    match await ensure_acr_login():
        case Ok(_): ...
        case Err(err):
            logger.error(f"docker.run({image!r}, ...) failed to auth to acr: {err!r}")

    env_args = [f"-e{k}={v}" for k,v in env.items()] if env else []
    mount_args = [f"-v{Path(k).as_posix()}:{Path(v).as_posix()}" for k, v in mounts.items()] if mounts else []
    async with contextlib.AsyncExitStack() as stack:
        if scope is None:
            scope = await stack.enter_async_context(manager.scope(group=group, timeout=timeout, cores=cores))

        docker_hostname = scope.host.ip
        if docker_hostname is None:
            docker_hostname = parse_docker_host(os.environ.get("DOCKER_HOST") or "127.0.0.1")
        bind_ip = "127.0.0.1" if docker_hostname == "127.0.0.1" else "0.0.0.0"
        port_args = [f"-p{bind_ip}::{port}" for port in ports] if ports else []

        # invariant: cid == None <=> the container is not started
        cid: Optional[str] = None
        async def cleanup():
            if cid is None:
                return
            proc = await scope.exec(
                "docker", "kill", cid,
                stdin=DEVNULL,
                stdout=DEVNULL,
                stderr=DEVNULL,
            )
            _ = await proc.wait()

        # ensure we kill + cleanup the container when we exit the run scope
        _ = await stack.enter_async_context(finalize(cleanup()))

        # start the container and wait for either the cidfile to appear or for docker run to exit
        # the launch is in a helper function so that we can shield it from cancellation
        td = await stack.enter_async_context(aio.tmpdir())
        async def launch_container() -> None:
            nonlocal cid
            cidfile = td / "cidfile"
            cmd_args = [
                "docker", "run", "--init", "-i", "--rm", "--platform", "linux/amd64", "--cidfile", cidfile.as_posix(),
                *env_args, *mount_args, *port_args, image, "sleep", "infinity"
            ]
            proc = await scope.exec(*cmd_args)
            try:
                async with asyncio.timeout(CONTAINER_SPAWN_TIMEOUT), asyncio.TaskGroup() as tg:
                    early_wait = tg.create_task(proc.wait(), name=f"docker.run() -> proc.wait() pid={proc.pid}")
                    watch_task = tg.create_task(watch_file(cidfile), name=f"docker.run() -> watch_file({cidfile})")
                    _ = await asyncio.wait((watch_task, early_wait), return_when=asyncio.FIRST_COMPLETED)
                    _ = watch_task.cancel()
                    _ = early_wait.cancel()
            except TimeoutError:
                logger.error("timeout waiting for container spawn")
            if await cidfile.exists():
                cid = (await cidfile.read_text()).strip()

        # shield container creation to avoid leaking cids if cancelled
        await shield_and_wait(launch_container())
        # only needed because pyright doesn't see the potential update in launch_container()
        cid = cast(Optional[str], cid)

        # if we reach here and cid is None, `docker run` must have exited -- not much we can do
        if cid is None:
            raise RuntimeError("docker run did not write container ID")

        logger.info(f"started docker {image} cid {cid}")
        # wait until we're sure the container is running
        proc = await scope.exec(
            "docker", "events",
            "--filter", f"container={cid}",
            "--filter", "event=start",
            "--since", "0",
            stdin=DEVNULL,
            stdout=PIPE
        )
        assert proc.stdout is not None
        _ = await proc.stdout.readline()
        proc.kill()
        _ = await proc.wait()

        port_map: dict[int, HostPort] = {}
        if ports:
            proc = await scope.exec("docker", "container", "port", cid, stdout=PIPE)
            stdout, _ = await proc.communicate()

            connect_hostname = scope.host.ip or docker_hostname
            # 8080/tcp -> 0.0.0.0:32768
            for a, b in re.findall(r"(\d+)/[^ ]+ -> .+?:(\d+)$", stdout.decode(), flags=re.MULTILINE):
                port_map[int(a)] = HostPort(connect_hostname, int(b))

        yield DockerRun(scope, cid, port_map)

class ImageBuildError(CRSError):
    pass

@requireable
async def docker_pull(scope: DockerScope, image_name: str, *, tries: int=2) -> Result[None]:
    for _ in range(tries):
        proc = await scope.exec("docker", "pull", image_name)
        if await proc.wait() == 0:
            return Ok(None)
        logger.warning("retrying image pull: {image_name}", image_name=image_name)
        require(await ensure_acr_login(force=True))
        await asyncio.sleep(1)
        logger.warning("retry got to login")
    return Err(CRSError(f"failed to pull image: {image_name!r}"))

@requireable
async def build_image(scope: DockerScope, project_dir: Path, image_name: str) -> Result[None]:
    require(await ensure_acr_login())
    is_remote_image = REGISTRY_DOMAIN and image_name.startswith(REGISTRY_DOMAIN)

    # 1. inspect
    proc = await scope.exec("docker", "image", "inspect", image_name, stdout=DEVNULL, stderr=DEVNULL)
    if await proc.wait() == 0:
        return Ok(None)

    # 2. pull
    if is_remote_image:
        if (await docker_pull(scope, image_name, tries=1)).is_ok():
            return Ok(None)

    # 3. build
    logger.info(f"building image {image_name} in {project_dir.as_posix()}...")
    proc = await scope.exec("docker", "build", "--platform", "linux/amd64", "-t", image_name, project_dir.as_posix())
    if await proc.wait() != 0:
        return Err(ImageBuildError(f"failed to build image {image_name!r}"))

    # 4. push (it's ok if this fails)
    if is_remote_image:
        proc = await scope.exec("docker", "push", image_name)
        _ = await proc.wait()

    return Ok(None)

@requireable
async def get_image_workdir(
    scope: DockerScope,
    image_name: str,
) -> Result[str]:
    require(await ensure_acr_login(force=True))

    proc = await scope.exec("docker", "image", "inspect", image_name, stdout=DEVNULL, stderr=DEVNULL)
    if await proc.wait() != 0:
        # 2. pull
        if (await docker_pull(scope, image_name)).is_err():
            return Err(CRSError(f"get_image_workdir() could not pull image {image_name!r}"))

    proc = await scope.exec(
        "docker", "image", "inspect", "-f", "{{.Config.WorkingDir}}", image_name,
        stdin=DEVNULL, stdout=PIPE, stderr=PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        return Err(CRSError(f"docker error: {stderr.decode(errors='replace')}"))
    return Ok(stdout.decode().strip())

# TODO: everything here besides _many/_tar commands should probably just be a VFS
# also all of the vmany commands should probably just move to blob storage
async def vmkdir(run: DockerRun, path: str) -> Result[None]:
    async with run.exec_scoped("mkdir", "-p", "--", path) as proc:
        _ = await proc.communicate()
        if proc.returncode != 0:
            return Err(CRSError(f"could not mkdir: {path}"))
    return Ok(None)

async def vrm(run: DockerRun, path: str) -> Result[None]:
    async with run.exec_scoped("rm", "-rf", "--", path) as proc:
        _ = await proc.communicate()
        if proc.returncode != 0:
            return Err(CRSError(f"could not rm: {path}"))
    return Ok(None)

async def vrm_many(run: DockerRun, paths: Collection[str]) -> Result[None]:
    if len(paths) == 0:
        return Ok(None)
    async with run.exec_scoped("xargs", "-0r", "rm", "-rf", "--", stdin=PIPE, stdout=DEVNULL, stderr=PIPE) as proc:
        _, stderr = await proc.communicate(("\0".join(paths)).encode())
        if proc.returncode != 0:
            return Err(CRSError(f"failed to rm: {stderr!r}"))
    return Ok(None)

@dataclass(frozen=True)
class Layer:
    path: str
    extract_under: str

@dataclass(frozen=True)
class TarFileLayer(Layer):
    tar_path: Path

@dataclass(frozen=True)
class TarBytesLayer(Layer):
    tar_data: io.BytesIO

@dataclass(frozen=True)
class CommandLayer(Layer):
    cmd: tuple[str, ...]

# FIXME: tars should live in blob storage, CRS box should have no reason to send a tar directly to docker from disk
async def vwrite_tar(run: DockerRun, path: str, tar: Path | io.BytesIO, extract_under: str = '.') -> Result[None]:
    async with run.exec_scoped("mkdir", "-p", path) as proc:
        if await proc.wait() != 0:
            return Err(CRSError(f"failed to mkdir at {path}"))

    cmd = ["tar", "xf", "-", "-C", path]
    if extract_under != '.':
        cmd += ["--strip-components", str(len(Path(extract_under).parts)), extract_under]

    with contextlib.ExitStack() as stack:
        if isinstance(tar, Path):
            stdin = stack.enter_context(open(tar, "rb")) # noqa: ASYNC230; sync open should be ~immediate
            input = None
        else:
            stdin = PIPE
            input = tar.getvalue()
        async with run.exec_scoped(*cmd, stdin=stdin) as proc:
            _ = await proc.communicate(input=input)
            if proc.returncode != 0:
                return Err(CRSError(f"could not write tar to {path}"))
    return Ok(None)

async def vwrite_layers(run: DockerRun, dst: str | Path, layers: Iterable[Layer]) -> Result[None]:
    for layer in layers:
        match layer:
            case TarFileLayer(path=p, tar_path=tar_path):
                res = await vwrite_tar(run, (Path(dst) / p).as_posix(), tar_path, layer.extract_under)
            case TarBytesLayer(path=p, tar_data=tar_data):
                res = await vwrite_tar(run, (Path(dst) / p).as_posix(), tar_data, layer.extract_under)
            case CommandLayer(path=p, cmd=cmd):
                async with run.exec_scoped(
                    docker_args=("-w", os.path.join(dst, p)),
                    *cmd,
                ) as proc:
                    _ = await proc.wait()
                    res = Ok(None) if proc.returncode == 0 else Err(CRSError("CommandLayer command returned nonzero exit code"))
            case _:
                return Err(CRSError(f"unsupported Layer type: {layer.__class__}"))

        if res.is_err():
            logger.error(f"failed to write vfs into build container: {repr(res)}")
            return Err(CRSError(f"could not write vfs: {res}"))
    return Ok(None)

async def vwrite(run: DockerRun, files: dict[str, bytes]) -> Result[None]:
    if not files:
        return Ok(None)
    if len(files) == 1:
        # don't bother with that tar stuff with 1 file
        for path, data in files.items():
            async with run.exec_scoped("tee", path, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL) as proc:
                _ = await proc.communicate(input=data)
                if proc.returncode == 0:
                    return Ok(None)
    fileobj = io.BytesIO()
    with tarfile.open(mode="w", fileobj=fileobj) as tf:
        for path, contents in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(contents)
            tf.addfile(info, io.BytesIO(contents))
        _ = fileobj.seek(0)
        return await vwrite_tar(run, "/", fileobj)

@requireable
async def vread(run: DockerRun, path: str) -> Result[bytes]:
    return Ok(next(iter((require(await vread_many(run, [path])).values()))))

async def vread_many(run: DockerRun, paths: Collection[str], ignore_allowed: bool = False) -> Result[dict[str, bytes]]:
    if len(paths) == 0:
        return Ok({})

    # note that we may have enough things to read that this exceeds OS limits on cli lengths, so we
    # need to do something fancier than passing all paths as an arg
    ignore_flags = ["--warning=no-file-changed", "--ignore-failed-read"] if ignore_allowed else []
    cmd = [
        "tar", *ignore_flags, "-cf", "-", "--null", "--verbatim-files-from", "--files-from=/dev/stdin",
    ]
    async with run.exec_scoped(*cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        stdout, stderr = await proc.communicate(("\0".join(paths)).encode())
        if proc.returncode != 0:
            return Err(CRSError(f"could not read files: {stderr!r}"))

    def extract():
        res: dict[str, bytes] = {}
        with tarfile.open(mode="r", fileobj=io.BytesIO(stdout)) as tf:
            for ti in tf.getmembers():
                fileobj = tf.extractfile(ti)
                # may be none for a directory
                if fileobj is not None:
                    res[ti.name] = fileobj.read()
        return res

    res = await asyncio.to_thread(extract)
    return Ok(res)

async def vls(run: DockerRun, dirname: str) -> set[str]:
    cmd = ["find", dirname, "-maxdepth", "1", "-printf", r"%P\0"]
    async with run.exec_scoped(*cmd, stdout=PIPE) as proc:
        stdout, _ = await proc.communicate()
    return {x.decode(errors="replace") for x in stdout.split(b"\0") if x}
