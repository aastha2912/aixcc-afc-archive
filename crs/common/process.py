from asyncio.subprocess import DEVNULL, PIPE, Process
from typing import Any, AsyncIterator, Self, Optional
import asyncio
import contextlib
import textwrap

from crs_rust import logger

from crs.common.utils import finalize, shield_and_wait

MAX_OUTPUT_LENGTH = 32
READ_LIMIT = 64 * 1024

def trim(output: bytes):
    return textwrap.shorten(output.decode(errors='replace'), MAX_OUTPUT_LENGTH)

class ProcRes:
    def __init__(self, stdout: Optional[bytes], stderr: Optional[bytes], returncode: Optional[int] = None, timedout: bool = False) -> None:
        self.stdout = stdout or b""
        self.stderr = stderr or b""
        self.returncode = returncode
        self.timedout = timedout

    @staticmethod
    def dummy_success(output: str = ""):
        return ProcRes(output.encode(), b"", 0, False)

    @staticmethod
    def dummy_failure(output: str = ""):
        return ProcRes(b"", output.encode(), -1, False)

    @property
    def output(self) -> str:
        stderr = (self.stderr + b"\n" if self.stderr else b"")
        return (stderr + self.stdout).decode(errors="replace")

    def __repr__(self) -> str:
        return f"ProcRes(returncode={self.returncode}, timedout={self.timedout}, stdout={repr(trim(self.stdout))}, stderr={repr(trim(self.stderr))})"

TERMINATE_TIMEOUT = 5.0

class ProcessScope:
    done: bool
    processes: set[Process]
    timeout: asyncio.Timeout

    def __init__(self, timeout: float | None = None):
        self.done = False
        self.processes = set()
        self.timeout = asyncio.timeout(timeout)

    @classmethod
    @contextlib.asynccontextmanager
    async def new(cls, *, timeout: Optional[float] = None) -> AsyncIterator[Self]:
        scope = cls(timeout=timeout)
        logger.debug(f"[ProcessScope] enter scope={id(scope)} timeout={scope.timeout}")
        async def cleanup():
            return await scope._exit()
        async with finalize(cleanup()):
            async with scope.timeout:
                yield scope

    async def _exit(self):
        logger.debug(f"[ProcessScope] exit scope={id(scope)} timeout={self.timeout}")
        self.done = True

        deadline = self.timeout.when()
        term_deadline = asyncio.get_running_loop().time() + TERMINATE_TIMEOUT
        term_deadline = term_deadline if deadline is None else min(deadline, term_deadline)

        # attempt to terminate and wait on all processes
        for proc in self.processes:
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
                # NOTE: I'm a little spooked we've seen ProcessLookupError while proc.returncode is None
                # as it could mean we have a chance to kill unknown processes here

        try:
            async with asyncio.timeout_at(term_deadline), asyncio.TaskGroup() as tg: # noqa: ASYNC100 ; false positive
                for proc in self.processes:
                    _ = tg.create_task(proc.wait(), name=f"proc.wait() pid={proc.pid}")
        except Exception:
            pass

        # kill any remaining processes
        for proc in self.processes:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

        self.processes.clear()

    def __del__(self):
        if self.processes:
            logger.error(f"[ProcessScope] leaked ({len(self.processes)}) processes: {self.processes}")

    async def exec(self, cmd: str, *args: str, **kwargs: Any) -> Process:
        cmdstr = ' '.join(([cmd] + list(args)))
        if self.done:
            raise RuntimeError(f"[ProcessScope] exec({cmdstr!r}) called after scope exit scope={id(self)}")

        logger.debug(f"[ProcessScope] exec({cmdstr!r}) scope={id(self)}")
        async def launch():
            p = await asyncio.create_subprocess_exec(cmd, *args, **kwargs) # noqa: CRS100; safe because it's shielded
            self.processes.add(p)
            return p
        p = await shield_and_wait(launch())
        return p

scope = ProcessScope.new

@contextlib.asynccontextmanager
async def run(cmd: str, *args: str, timeout: float | None = None, **kwargs: Any) -> AsyncIterator[Process]:
    async with scope(timeout=timeout) as local_scope:
        yield await local_scope.exec(cmd, *args, **kwargs)

class Reader:
    process: Optional[Process]
    stdout_blocks: list[bytes]
    stderr_blocks: list[bytes]

    def __init__(self, process: Optional[Process] = None):
        self.process = process
        self.stdout_blocks = []
        self.stderr_blocks = []

    # TODO: support stdin?
    async def communicate(self) -> ProcRes:
        process = self.process
        if process is None:
            raise RuntimeError("process.Reader.communicate() without a process")

        if process.stdin is not None:
            process.stdin.close()

        async with asyncio.TaskGroup() as tg:
            async def read_stdio(f: Optional[asyncio.StreamReader], dst: list[bytes]) -> None:
                if f is None:
                    return
                while (data := await f.read(READ_LIMIT)):
                    dst.append(data)
            _ = tg.create_task(read_stdio(process.stdout, self.stdout_blocks), name=f"process.Reader.communicate():stdout pid={process.pid}")
            _ = tg.create_task(read_stdio(process.stderr, self.stderr_blocks), name=f"process.Reader.communicate():stderr pid={process.pid}")
            _ = await process.wait()

        return self.result()

    def result(self, timedout: bool=False) -> ProcRes:
        stdout = b"".join(self.stdout_blocks)
        stderr = b"".join(self.stderr_blocks)
        returncode = -1 if self.process is None else self.process.returncode
        return ProcRes(stdout, stderr, returncode, timedout=timedout)


# NOTE: I don't love this existing - all of the callers are already in a ProcessScope
async def run_to_res(cmd: str, *args: str, timeout: float | None = None, capture_output: bool = False, **kwargs: Any) -> ProcRes:
    stdin = kwargs.pop("stdin", DEVNULL)
    pipe = PIPE if capture_output else None
    reader = Reader()
    try:
        async with scope(timeout=timeout) as local_scope:
            proc = await local_scope.exec(cmd, *args, stdin=stdin, stdout=pipe, stderr=pipe, **kwargs)
            reader = Reader(proc)
            return await reader.communicate()
    except TimeoutError:
        return reader.result(timedout=True)
