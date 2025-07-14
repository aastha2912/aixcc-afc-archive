from pydantic import BaseModel, Field
from typing import Optional

from crs.agents.crsbase import CRSBase
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass
from crs.modules.kaitai import compile_descriptor, KaitaiParser, run_python, DEFAULT_KAITAI_TIMEOUT
from crs.common.types import CRSError, Err, Ok, Result, Tool, Message
from crs.common.utils import cached_property, requireable, require, tool_wrap
from crs.modules.project import Harness



@XMLVerifyClass
class GenerateKaitaiResult(BaseModel):
    summary: str = Field(
        description="A summary of your steps to arrive at the working kaitai descriptor. Note: before returning, you must confirm your descriptor works as expected."
    )


class GenerateKaitaiAgent(XMLAgent[GenerateKaitaiResult]):
    name = "generate_kaitai"

    @property
    def return_type(self):
        return GenerateKaitaiResult

    # override XMLAgent.get_result
    def get_result(self, msg: Message) -> GenerateKaitaiResult | Message | None:
        if not msg.tool_calls and not self.can_terminate:
            return Message(
                role="user",
                content=(
                    "You may not return a result until you have successfully parsed the corpus. "
                    "Keep iterating on your descriptor until you confirm it can parse the whole corpus "
                )
            )
        return super().get_result(msg)

    @cached_property
    def tools(self) -> dict[str, Tool]:
        return {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "compile_kaitai": tool_wrap(self.compile_kaitai),
            "python_script": tool_wrap(self.run_python),
        }

    @requireable
    async def compile_kaitai(self, descriptor: str) -> Result[str]:
        parser = require(await compile_descriptor(descriptor))

        example = f"import {parser.name}"
        if parser.structures:
            example = f"from {parser.name} import {', '.join(parser.structures)}"

        # backup
        _prev = self.parser
        # test with python
        self.parser = parser
        match await self.parser.decode_all(self.corpus):
            case Err(crserr):
                if _prev is not None:
                    # rollback to previously succeeded parser
                    self.parser = _prev
                return Err(
                    CRSError(
                        "WARNING: Your parser was successfuly compiled, but failed to parse the corpus. "
                        "Review the result carefully. If you identify any incorrectly written components in your Kaitai descriptor"
                        "—whether through debugging tools or intuition—fix them and retry `compile_kaitai`. "
                        "However, if you determine that the corpus is non-benign and may cause a crash in the target project (or the parser), "
                        "document the reason and finish the conversation once you are confident in the descriptor's correctness.\n"
                        f"Error: {crserr.error}\n",
                        extra=crserr.extra,
                    )
                )
            case Ok():
                pass

        _num_tested = len(self.corpus)
        self.can_terminate = True
        return Ok(
            f"The parser is successfully compiled and tested reading the {_num_tested} corpus seeds without exception. "
            f"But that may not guarantee correctness. We've saved your kaitai parser. "
            f"Before terminating the conversation, check the parser correctness with the available tools. "
            f"You can import the parser with `{example}` when using the tool `run_python`."
        )

    @requireable
    async def run_python(self, snippet: str) -> Result[str]:
        return await run_python(snippet, self.corpus, self.parser, trim_output=True)

    def __init__(
        self,
        crs: "CRSGenerateKaitai",
        harness: Harness,
        harness_func_src: Optional[str],
        tips: str = "",
        corpus: dict[str, bytes] = {},
        timeout: float | None = DEFAULT_KAITAI_TIMEOUT,
    ):
        assert len(corpus) > 0, "cannot use GenerateKaitaiAgent with empty corpus"
        self.crs = crs
        self.harness = harness
        self.harness_func_src = harness_func_src
        self.tips = tips
        self.corpus = corpus
        self.timeout = timeout
        # compiled result
        self.parser: KaitaiParser | None = None
        self.can_terminate = False
        super().__init__()


class CRSGenerateKaitai(CRSBase):
    @requireable
    async def generate_kaitai(
        self,
        harness_num: int,
        corpus: dict[str, bytes]
    ) -> Result[KaitaiParser]:
        """
        Every challenge harness takes input as a buffer of bytes. However, this
        may not match up with what we learn about a vulnerable code path (for example,
        it may be triggered by packets from a network socket). This tool is intended
        to produce a kaitai structure to represent the input. There may be some description
        about the code as well.

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
            if the kaitai structure compiled success, this contains a
            generated kaitai structure, compiled python code and their names.
        """
        if len(corpus) == 0:
            return Err(CRSError("empty corpus provided"))

        # retrieve the harness from the project
        harness = require(self.project.check_harness(harness_num))

        if await self.is_text_proto_fuzzer(harness):
            return Err(CRSError("protobuf text format does not need a kaitai parser"))

        tips = await self.harness_tips(harness)

        harness_func_src = await self.project.read_harness_func(harness)
        # generate the kaitai descriptor form the harness
        agent = GenerateKaitaiAgent(self, harness, harness_func_src=harness_func_src, corpus=corpus, tips=tips)
        _ = await agent.run()
        if agent.parser is None:
            return Err(CRSError("No response from kaitai producer"))
        return Ok(agent.parser)