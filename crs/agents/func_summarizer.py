
from pydantic import BaseModel, Field
from typing import Optional

from crs.agents.crsbase import CRSBase
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass
from crs.common.types import Result, Ok, Err, Tool, CRSError
from crs.common.utils import cached_property, requireable, require, tool_wrap

@XMLVerifyClass
class Summary(BaseModel):
    summary: str = Field(description="A short description of the conditions required for the function to be safe")
    always_safe: bool = Field(description="True if and only if the function is safe against all potential inputs")


class FunctionSummarizer(XMLAgent[Summary]):
    name = "function_summarizer"

    @cached_property
    def tools(self) -> dict[str, Tool]:
        return {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
        }

    @property
    def return_type(self):
        return Summary

    def __init__(self, crs: CRSBase, function_name: str, function_body: str):
        self.crs = crs
        self.function_name = function_name
        self.function_body = function_body
        super().__init__()

class LLMFailure(CRSError):
    pass

class CRSFunctionSummarizer(CRSBase):
    @requireable
    async def summarize_func(
        self,
        func_name: str,
        func_path: Optional[str] = None,
    ) -> Result[Summary]:
        definition = require(await self.searcher.read_definition(func_name, path=func_path, display_lines=False))
        fs = FunctionSummarizer(self, func_name, definition['contents'])
        summarizer_result = await fs.run()
        if summarizer_result.response:
            return Ok(summarizer_result.response)
        return Err(LLMFailure(f"no summary returned for {func_name}"))
