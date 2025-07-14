from pydantic import BaseModel, Field

from opentelemetry import trace

from crs import config
from crs.agents.crsbase import CRSBase
from crs.agents.agent import CRSAgent
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass
from crs.agents.vuln_analyzer import AnalyzedVuln
from crs.common.types import Ok, Err, Result, Tool, CRSError
from crs.common.utils import cached_property, tool_wrap
from crs.modules.project import DeltaTask


MIN_CONFIDENCE = 2

@XMLVerifyClass
class DiffAnalysis(BaseModel):
    change_desc: str = Field(description="a brief description of the code changes in the diff, and whether it is likely benign or not")
    vuln: list[AnalyzedVuln] = Field(description=("only if there are found vulnerabilities, additional information about them. Otherwise omit the vuln section entirely"))


class CRSDiffAgent(CRSAgent[DiffAnalysis, 'CRSDiff'], XMLAgent[DiffAnalysis]):
    name = "diff_analyzer"

    @property
    def return_type(self) -> type[DiffAnalysis]:
        return DiffAnalysis

    @cached_property
    def tools(self) -> dict[str, Tool]:
        return {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references":  tool_wrap(self.crs.searcher.find_references),
        }

    def __init__(self, crs: 'CRSDiff', diff: str):
        self.diff = diff
        super().__init__(crs)

class CRSDiff(CRSBase):
    async def analyze_diff(self, rawdiff: bool = False) -> Result[DiffAnalysis]:
        """
        Use this function to analyze the diff for the current task. If the current
        task is not a DeltaTask, this will immediately return an error.
        This will then return a text based description of any vulnerabilities found
        in that diff. However, this data is sourced from an AI agent who may be
        confused or forget things. It may report vulnerabilties where none exist.
        Running this function multiple times may produce different results.

        Returns
        -------
        dict
            the results, or any errors
        """
        if not isinstance(self.task, DeltaTask):
            return Err(CRSError("self.task is not a DeltaTask, no diff available"))

        pruned_diff = await self.task.pruned_diff(rawdiff=rawdiff)
        with config.telem_tracer.start_as_current_span(
            "analyze_diff",
            attributes={
                "crs.action.name": "analyze_diff", "crs.action.category": "static_analysis",
                "crs.debug.pruned_diff_size": len(pruned_diff), "crs.debug.raw_diff_size": len(self.task.diff),
            },
            record_exception=False,
        ) as span:
            agent = CRSDiffAgent(crs=self, diff=pruned_diff)
            res = (await agent.run()).response

            span = trace.get_current_span()
            if res is not None:
                span.add_event(
                    f"diff analysis complete",
                    attributes={"crs.debug.analyzer.vulns_found": len(res.vuln)}
                )
                return Ok(res)
            return Err(CRSError("no diff info returned"))
