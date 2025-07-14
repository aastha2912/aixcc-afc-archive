from asyncio.subprocess import PIPE
import os
from pydantic import BaseModel, ConfigDict
from typing import Iterable, Optional

from crs import config
from crs.common.utils import trim_tool_output, require, requireable
from crs.common.types import Result, Ok, Err, CRSError
from crs.common import docker, process
from crs.common.constants import MAX_POV_LENGTH

from crs_rust import logger

# note: Dockerfile in utils/python_sandbox
# pushed to dockerhub for testing, and pushed to our azure registry in production
SANDBOX_IMAGE_NAME = f"{config.REGISTRY_DOMAIN}/python_sandbox" if config.REGISTRY_DOMAIN else 'tjbecker/python_sandbox:0.3.1'
SANDBOX_TIMEOUT = 180

def sanitize_stderr(stderr: str):
    # make an attempt to remove sandbox references, it's just a few lines,
    # but better to not have it if possible
    try:
        lines = stderr.splitlines()
        if not any([l.startswith("Traceback (") for l in lines]):
            return stderr
        first_bad_line = 'File "<string>", line 1, in <module>'
        last_bad_line = "code = compile(f.read(), fname, 'exec')"
        bad_ends = []
        if bad_starts := [i for i,l in enumerate(lines) if first_bad_line in l]:
            if bad_ends := [i for i,l in enumerate(lines) if last_bad_line in l]:
                if len(bad_starts) != len(bad_ends):
                    return stderr

        start: list[Iterable[int]] = []
        bad_idxs = set(sum([list(range(i,j+1)) for i,j in zip(bad_starts, bad_ends)], start=start))
        return "\n".join([l for i,l in enumerate(lines) if i not in bad_idxs])
    except Exception:
        return stderr

class PythonRunResults(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool
    stdout: str
    stderr: str
    files: dict[str, Result[bytes]]

@requireable
async def run_python(
    source_code: str,
    timeout: float = SANDBOX_TIMEOUT,
    max_size: int = MAX_POV_LENGTH,
    write_files: Optional[dict[str, bytes]] = None,
    trim_output: bool = True
) -> Result[PythonRunResults]:
    reader = process.Reader()
    files: dict[str, Result[bytes]] = {}
    python_finished = False
    debug_loc = None
    try:
        async with docker.run(SANDBOX_IMAGE_NAME, timeout=timeout, group=docker.DockerGroup.Misc) as run:
            to_write = {"/workdir/source.py": source_code.encode()}
            if write_files:
                to_write.update(**write_files)
            # write our source code, add python and arguments and stuff
            require(await docker.vwrite(run, to_write))
            stub = "import random, runpy; random.seed(1337); runpy.run_path('source.py', run_name='__main__')"
            proc = await run.exec(
                "python", "-c", stub,
                stdout=PIPE, stderr=PIPE,
                docker_args=("-w", "/workdir"),
            )
            reader = process.Reader(proc)
            res = await reader.communicate()
            if trim_output:
                res.stdout, res.stderr = trim_tool_output(res.stdout, ratio=1/4), trim_tool_output(res.stderr, ratio=1/4)
            python_finished = True
            debug_loc = 0

            # first list the files and check their lengths?
            proc = await run.exec(
                "find", "/workdir", "-type", "f", "-exec", "stat", "--printf", r"%n\0%s\0\0", "{}", r";",
                stdout=PIPE, stderr=PIPE,
            )
            debug_loc = 1
            find_reader = process.Reader(proc)
            size_res = await find_reader.communicate()
            debug_loc = 2
            sizes = {e.split(b"\0")[0].decode(errors="replace"):int(e.split(b"\0")[1]) for e in size_res.stdout.split(b"\0\0") if e}
            to_fetch: list[str] = []
            for fname, size in sizes.items():
                if size > max_size:
                    files[fname] = Err(CRSError(f"{fname} is too large at {size} bytes (max allowable is {max_size} bytes)"))
                else:
                    to_fetch.append(fname)
            debug_loc = 3
            for p,v in require(await docker.vread_many(run, to_fetch)).items():
                files[os.path.relpath(p, "workdir/")] = Ok(v)
            _ = files.pop("source.py", None)
    except TimeoutError:
        if not python_finished:
            res = reader.result()
            res.stderr += b"\nError: python process did not terminate"
        else:
            logger.error(f"run_python timed out after python finished. {debug_loc=}")
            return Err(CRSError("A fatal error occurred AFTER running the Python, please try again"))

    return Ok(PythonRunResults(
        success=res.returncode == 0,
        stdout=res.stdout.decode("utf-8", errors="replace"),
        stderr=sanitize_stderr(res.stderr.decode("utf-8", errors="replace")),
        files=files,
    ))
