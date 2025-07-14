from crs.common.aio import Path
from pydantic import BaseModel, Field
from typing import Any, Optional

from opentelemetry import trace

from crs import config
from crs.agents.tool_required_agent import ToolRequiredAgent, ToolVerifyClass
from crs.agents.crsbase import CRSBase
from crs.modules.project import BuildArtifacts, Harness
from crs.common.types import Ok, Err, Result, POVRunData, Tool, CRSError, ToolResult, ToolError
from crs.common.utils import cached_property, requireable, require, tool_wrap, trim_tool_output

DEBUG_PRINT_PREFIX = "CRS_DEBUG"
MAX_DEBUG_PRINTS = 100
MAX_DEBUG_PRINT_LEN = 256

@ToolVerifyClass
class DebugResult(BaseModel):
    summary: str = Field(description='a summary of the actions taken to answer the question(s)')
    answer: str = Field(description='the answer(s) to any question(s) in the debug query')

class CRSDynamicDebugAgent(ToolRequiredAgent[DebugResult]):
    name = "dynamic_debugger"

    @property
    def return_type(self):
        return DebugResult

    @requireable
    async def gdb_exec(self, source_file: str, line_number: int, commands: str) -> Result[str]:
        breakpoint = f"{Path(source_file).name}:{line_number}"
        return await self.crs.debugger.gdb_exec(self.harness_num, self.contents, breakpoint, commands.splitlines())

    @requireable
    async def jdb_exec(self, className: str, line_number: int, commands: str) -> Result[str]:
        breakpoint = f"{className}:{line_number}"
        return await self.crs.debugger.jdb_exec(self.harness_num, self.contents, breakpoint, commands.splitlines())

    async def artifacts_hook[R](self, res: ToolResult[R], *args: Any, **kwargs: Any):
        match await self.crs.project.build(self.crs.project.info.default_build_config):
            case Ok(artifacts):
                self.artifacts = artifacts
            case Err(_):
                self.artifacts = None
                return ToolError("the build failed to produce artifacts", extra=res.model_dump())
        return res

    async def query_coverage(self, target_file: str, target_line: int):
        return await self.crs.coverage.query_coverage_raw(self.harness_num, self.contents, target_file, target_line)

    @requireable
    async def get_output(self):
        artifacts = require(await self.crs.project.build_default())
        harness = require(await self.crs.project.init_harness_info())[self.harness_num]
        res = await artifacts.run_pov(self.contents, harness.name)
        return Ok(trim_tool_output(res.output))

    @cached_property
    def _tools(self) -> dict[str, Tool]:
        tools: dict[str, Tool] = {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.project.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "query_coverage": tool_wrap(self.query_coverage),
            "get_output": tool_wrap(self.get_output)
        }
        match self.crs.project.info.language:
            case "c"|"c++": tools["gdb_exec"] = tool_wrap(self.gdb_exec)
            case "jvm": tools["jdb_exec"] = tool_wrap(self.jdb_exec)
            case _: pass
        return  tools

    def __init__(
        self,
        crs: 'CRSDynamicDebug',
        harness_num: int,
        pov_python: Optional[str],
        question: str,
        additional_info: str,
        contents: bytes
    ):
        self.crs = crs
        self.harness_num = harness_num
        self.pov_python = pov_python
        self.question = question
        self.additional_info = additional_info
        self.contents = contents
        self.artifacts: Optional[BuildArtifacts] = None
        super().__init__()

class CRSDynamicDebug(CRSBase):
    async def _run_debug_agent(self, harness: Harness, agent: CRSDynamicDebugAgent):
        res = await agent.run()
        turn_limit_flag = False
        if not res.terminated or res.response is None:
            turn_limit_flag = True
            agent.append_user_msg(
                "You are being stopped. "
                "Any results you have or information you have learned so far that may be pertinent "
                "to your original instructions should be summarized. "
                "Anything you missed that you were planning to do but could not finish should also be summarized. "
                "This summary will serve as your response to their instruction.\n"
                "<important>YOU MUST USE THE 'terminate' TOOL. Never call any other tools and only use the 'terminate' tool.</important>"
            )
            res = await agent.run(max_iters=1)

        if res.response is not None:
            span = trace.get_current_span()
            span.add_event(
                "debug complete",
                {"crs.action.target.harness": harness.name}
            )
            if turn_limit_flag:
                res.response.answer = "<INFO>This answer is based on currently available information. Some areas may require additional investigation.</INFO>\n" + res.response.answer
            return Ok(res.response)
        else:
            return Err(CRSError("no response returned"))

    @config.telem_tracer.start_as_current_span("debug_pov", record_exception=False)
    @requireable
    async def debug_pov(
        self,
        harness_num: int,
        pov_python: str,
        question: str,
        additional_info: str = "",
    ) -> Result[DebugResult]:
        # step 0: make sure we have a valid harness num and PoV that we can use for testing
        harness = require(self.project.check_harness(harness_num))
        contents = require(await self.project.build_pov(pov_python))

        agent = CRSDynamicDebugAgent(
            crs=self, harness_num=harness_num, pov_python=pov_python,
            question=question, additional_info=additional_info, contents=contents
        )
        return await self._run_debug_agent(harness, agent)


    def get_debug_pov_raw(self, pov: POVRunData):
        @config.telem_tracer.start_as_current_span("debug_pov_raw", record_exception=False)
        @requireable
        async def debug_pov_raw(
            question: str,
            additional_info: str = "",
        ) -> Result[DebugResult]:
            harnesses = require(await self.project.init_harness_info())
            harness_nums = [i for i, x in enumerate(harnesses) if x.name == pov.harness]
            if len(harness_nums) != 1:
                return Err(CRSError(f"could not find harness for {pov.harness}"))

            agent = CRSDynamicDebugAgent(
                crs=self, harness_num=harness_nums[0], pov_python=None,
                question=question, additional_info=additional_info, contents=pov.input
            )
            return await self._run_debug_agent(harnesses[harness_nums[0]], agent)
        debug_pov_raw.__qualname__ = "CRSDynamicDebugAgent.debug_pov_raw"

        return debug_pov_raw
