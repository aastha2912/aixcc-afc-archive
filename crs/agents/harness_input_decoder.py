import asyncio
import orjson

from crs.common.aio import Path
from pydantic import BaseModel, Field
from typing import Optional

from crs import config
from crs.common.types import Message, Tool, Decoder, DEFAULT_DECODER_TIMEOUT, Result, Ok, Err, CRSError
from crs.common.utils import cached_property, tool_wrap, require, requireable
from crs.modules.project import Harness
from crs.modules.python_sandbox import run_python
from crs.agents.crsbase import CRSBase
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass

TARGET_DECODINGS_DISPLAY_SIZE = 8192

with open(config.CRSROOT / ".." / "utils" / "rle.py", "rb") as f:
    RLE_PY_BYTES = f.read()

DECODE_PYTHON = r"""
from typing import Any

{decoder_python}

from rle import RLEPrettyPrinter
import json
from pathlib import Path

results = {{}}
for input in Path('/corpus').iterdir():
    try:
        results[input.name] = decode_input(input.read_bytes())
    except:
        print(f'Exception occured while processing the input {{input.as_posix()}}')
        raise
pp = RLEPrettyPrinter(width=128, sort_dicts=False)
print(json.dumps({{input: pp.pformat(res) for input,res in results.items()}}))
"""

class PythonHarnessInputDecoder(Decoder):
    decoder_python: str

    async def decode_all(
        self,
        corpus: dict[str, bytes],
        timeout: float = DEFAULT_DECODER_TIMEOUT,
        trim_output: bool = False
    ) -> Result[dict[str, str]]:
        write_files: dict[str, bytes] = {
            f"/corpus/{name}": value for name, value in corpus.items()
        }
        write_files["/workdir/rle.py"] = RLE_PY_BYTES
        code = DECODE_PYTHON.format(decoder_python=self.decoder_python)
        match await run_python(code, write_files=write_files, timeout=timeout, trim_output=trim_output):
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

        try:
            parsed: dict[str, str] = await asyncio.to_thread(orjson.loads, res.stdout.strip())
            return Ok(parsed)
        except Exception as e:
            return Err(CRSError(f"Error decoding result from python decoder: {e}", extra={"output": res.stdout}))

    def format(self) -> str:
        return (
            "<python>\n"
            f"{self.decoder_python}"
            "</python>\n"
        )


@XMLVerifyClass
class HarnessInputDecoderResult(BaseModel):
    summary: str = Field(
        description="A summary of your steps to arrive at the working harness input decoder. Note: before returning, you must confirm your decoder works as expected."
    )

class HarnessInputDecoderAgent(XMLAgent[HarnessInputDecoderResult]):
    @property
    def return_type(self):
        return HarnessInputDecoderResult

    @cached_property
    def tools(self) -> dict[str, Tool]:
        tools: dict[str, Tool] = {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "test_decoder": tool_wrap(self.test_decoder),
        }
        match self.crs.project.info.language:
            case "c"|"c++": tools["gdb_exec"] = tool_wrap(self.gdb_exec)
            case "jvm": tools["jdb_exec"] = tool_wrap(self.jdb_exec)
            case _: pass
        return tools


    # override XMLAgent.get_result
    def get_result(self, msg: Message) -> HarnessInputDecoderResult | Message | None:
        if not msg.tool_calls and not (self.parsed and self.debugged):
            return Message(
                role="user",
                content=(
                    "You may not return a result until you have successfully parsed the corpus and "
                    "confirmed its correctness using the debugger. "
                    "Keep iterating on your decoder until you confirm it can parse the whole corpus."
                )
            )
        return super().get_result(msg)

    @requireable
    async def gdb_exec(self, input_name: str, source_file: str, line_number: int, commands: str):
        if input_name not in self.corpus:
            return Err(CRSError(f"input {input_name} does not exist. Available inputs: {list(self.corpus.keys())}"))
        self.debugged = True
        input = self.corpus[input_name]
        breakpoint = f"{Path(source_file).name}:{line_number}"
        return await self.crs.debugger.gdb_exec(self.harness_num, input, breakpoint, commands.splitlines())

    @requireable
    async def jdb_exec(self, input_name: str,className: str, line_number: int, commands: str):
        if input_name not in self.corpus:
            return Err(CRSError(f"input {input_name} does not exist. Available inputs: {list(self.corpus.keys())}"))
        self.debugged = True
        input = self.corpus[input_name]
        breakpoint = f"{className}:{line_number}"
        return await self.crs.debugger.jdb_exec(self.harness_num, input, breakpoint, commands.splitlines())

    @requireable
    async def test_decoder(self, decoder_python: str):
        decoder = PythonHarnessInputDecoder(decoder_python=decoder_python)
        match await decoder.decode_all(self.corpus):
            case Err(crserr):
                return Err(
                    CRSError(
                        "WARNING: Your parser failed to parse the corpus. "
                        f"Error: {crserr.error}\n",
                        extra=crserr.extra,
                    )
                )
            case Ok(results):
                pass

        _num_tested = len(self.corpus)
        self.input_decoder = decoder
        self.parsed = True

        decodings = ""
        for name, result in results.items():
            decodings += (
                "<input>\n"
                f"<name>{name}</name>\n"
                f"<decoding>\n{result}\n</decoding>\n"
                "</input>\n"
            )
            if len(decodings) >= TARGET_DECODINGS_DISPLAY_SIZE:
                break

        message = (
            f"Your decoder successfully ran against {_num_tested} corpus inputs without exception. "
            f"But that may not guarantee correctness. Please confirm that the following few outputs "
            f"from your decoder look correct by using the provided debugger tools to inspect the "
            f"variables in the harness, comparing them with your output. If your output looks correct, "
            f"please terminate with your summary. "
            f"If it does not look correct, please test a corrected decoder.\n" +
            decodings
        )
        return Ok(message)

    def __init__(
        self,
        crs: "CRSHarnessInputDecoder",
        harness_num: int,
        harness: Harness,
        harness_func_src: Optional[str],
        tips: str = "",
        corpus: dict[str, bytes] = {},
    ):
        assert len(corpus) > 0, "cannot use HarnessInputDecoderAgent with empty corpus"
        self.crs = crs
        self.harness_num = harness_num
        self.harness = harness
        self.harness_func_src = harness_func_src
        self.tips = tips
        self.corpus = corpus
        # result
        self.input_decoder: PythonHarnessInputDecoder | None = None
        self.parsed = False
        self.debugged = False
        super().__init__()


class CRSHarnessInputDecoder(CRSBase):
    @requireable
    async def generate_decoder(
        self,
        harness_num: int,
        corpus: dict[str, bytes]
    ) -> Result[PythonHarnessInputDecoder]:
        """
        Every challenge harness takes input as a buffer of bytes. However, this
        may not match up with what we learn about a vulnerable code path (for example,
        it may be triggered by packets from a network socket). This tool is intended
        to produce a python decoder to represent the harness inputs in a human-readable way.
        There may be some descriptions about the code as well.

        This function uses an AI agent to help write it. Therefore there may be
        errors in the results. It may be run again to produce new results.

        Parameters
        ----------
        harness_num : int
            the (0 indexed) harness to target
        corpus : dict[str, bytes]
            a collection of test inputs for the harness

        Returns
        -------
        dict
            if an error occured, this contains an error message
            if the python decodes the corpus correctly, this contains the python
            `decode_input` function definition
        """
        if len(corpus) == 0:
            return Err(CRSError("empty corpus provided"))

        # retrieve the harness from the project
        harness = require(self.project.check_harness(harness_num))

        if await self.is_text_proto_fuzzer(harness):
            return Err(CRSError("protobuf text format does not need a python decoder"))

        tips = await self.harness_tips(harness)

        harness_func_src = await self.project.read_harness_func(harness)
        # generate the descriptor form the harness
        agent = HarnessInputDecoderAgent(self, harness_num, harness, harness_func_src=harness_func_src, corpus=corpus, tips=tips)
        _ = await agent.run()
        if agent.input_decoder is None:
            return Err(CRSError("No response from python decoder producer"))
        return Ok(agent.input_decoder)
