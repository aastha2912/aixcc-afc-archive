import asyncio
import orjson
import re

from typing import Optional

from crs.common import aio, process
from crs.common.aio import Path
from crs.common.types import Err, Ok, Result, CRSError, Decoder
from crs.common.utils import require, requireable
from crs.modules import python_sandbox

DEFAULT_KAITAI_TIMEOUT = 60


KAITAI_PYTHON_UTILS = """
import os
import json
import pprint

def kaitai_to_dict(obj):
    if isinstance(obj, list):
        return [kaitai_to_dict(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return {
            k: kaitai_to_dict(v)
            for k, v in vars(obj).items()
            if not k.startswith('_')  # Skip Kaitai internals like _io, _root, etc.
        }
    else:
        return obj

def kaitai_pprint(obj):
    return pprint.pformat(kaitai_to_dict(obj), sort_dicts=False, width=100000)
"""

async def run_python(
    source_code: str,
    corpus: dict[str, bytes],
    parser: Optional['KaitaiParser'],
    timeout: float = DEFAULT_KAITAI_TIMEOUT,
    trim_output: bool = False
):
    write_files: dict[str, bytes] = {
        f"/corpus/{name}": value for name, value in corpus.items()
    }
    if parser:
        write_files[f"/workdir/{parser.name}"] = parser.python.encode()

    match await python_sandbox.run_python(
        source_code,
        timeout=timeout,
        write_files=write_files,
        trim_output=trim_output
    ):
        case Err(err):
            return Err(
                CRSError(
                    f"Exception occured during python execution: {err.error}",
                    err.extra,
                )
            )
        case Ok(res):
            pass

    if not res.success:
        return Err(
            CRSError(
                "ERROR: python exited with non-zero return",
                extra={
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                },
            )
        )
    return Ok(res.stdout)

class KaitaiParser(Decoder):
    name: str
    ksy: str
    python: str
    structures: list[str]

    def format(self):
        return (
            f"<kaitai>\n" +
            f"<descriptor>\n" +
            f"{self.ksy}\n" +
            f"</descriptor>\n" +
            f"</kaitai>"
        )

    async def run_python(
        self,
        source_code: str,
        corpus: dict[str, bytes] = {},
        timeout: float = DEFAULT_KAITAI_TIMEOUT,
        trim_output: bool = False,
    ) -> Result[str]:
        return await run_python(source_code, corpus, self, timeout=timeout, trim_output=trim_output)

    @requireable
    async def decode_all(
        self,
        corpus: dict[str, bytes],
        timeout: float = DEFAULT_KAITAI_TIMEOUT,
        trim_output: bool = False
    ) -> Result[dict[str, str]]:
        code = (
            f"{KAITAI_PYTHON_UTILS}\n"
            f"from {Path(self.name).stem} import {', '.join(self.structures)}\n"
            f"results = {{}}\n"
            f"for Parser in [{', '.join(self.structures)}]:\n"
            f"    for input in os.listdir('/corpus'):\n"
            f"        try:\n"
            f"            results[input] = Parser.from_file(os.path.join('/corpus', input))\n"
            f"        except:\n"
            f"            print('Exception occured while processing the corpus /corpus/' + input)\n"
            f"            raise\n"
            f"print(json.dumps({{input: kaitai_pprint(res) for input, res in results.items()}}))\n"
        )
        res = require(await self.run_python(code, timeout=timeout, corpus=corpus, trim_output=trim_output))
        try:
            parsed: dict[str, str] = await asyncio.to_thread(orjson.loads, res.strip())
            return Ok(parsed)
        except Exception as e:
            return Err(CRSError(f"Error decoding result from kaitai decoder: {e}"))


async def compile_kaitai(
    ksy_path: Path,
    workdir: Path,
    timeout: Optional[float] = DEFAULT_KAITAI_TIMEOUT,
) -> Result[KaitaiParser]:
    """Run Kaitai Compiler(ksc) for the given ksy file and return a standard outputs."""
    result: process.ProcRes
    reader = process.Reader()
    try:
        async with process.run(
            "ksc",
            (await ksy_path.absolute()).as_posix(),
            "-t",
            "python",
            timeout=timeout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workdir,
        ) as proc:
            reader = process.Reader(proc)
            result = await reader.communicate()
    except TimeoutError:
        result = reader.result(True)
        result.stderr += b"\nERROR: python process did not terminate(timedout)"
    except Exception as e:
        return Err(CRSError(f"Unknown error encountered in ksc: {repr(e)}"))

    parser_path: Path | None = None
    if result.returncode == 0:
        results: list[Path] = []
        async with workdir.glob("*.py") as py_it:
            async for item in py_it:
                results.append(item)
        try:
            parser_path, = results
        except StopIteration:
            result.stderr += b"\nERROR: the compiled parser could not be found."
        except ValueError:
            # if multiple found
            result.stderr += b"\nERROR: multiple parsers were found."

    if parser_path is None:
        return Err(
            CRSError(
                f"Compile failed, fix the issues and retry compiling:\n"
                f"```\n{result.stdout.decode(errors='replace')}\n"
                f"{result.stderr.decode(errors="replace")}\n```"
            )
        )

    script = await parser_path.read_text(errors="replace")
    ksy = await ksy_path.read_text(errors="replace")

    return Ok(KaitaiParser(
        name=parser_path.name,
        ksy=ksy,
        python=script,
        structures=re.findall(r"^class (.+?)\(KaitaiStruct\):\s*$", script, re.M),
    ))


async def compile_descriptor(descriptor: str) -> Result[KaitaiParser]:
    async with aio.tmpdir() as workdir:
        ksy_path = workdir / "desc.ksy"
        _ = await ksy_path.write_text(descriptor)
        return await compile_kaitai(ksy_path, workdir)

@requireable
async def decode_inputs_with_kaitai(
    descriptor: str,
    corpus: dict[str, bytes]
) -> Result[dict[str, str]]:
    parser = require(await compile_descriptor(descriptor))
    return await parser.decode_all(corpus)
