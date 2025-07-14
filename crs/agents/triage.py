from typing import Optional, Literal

from crs.agents.tool_required_agent import ToolVerifyClass, ToolRequiredAgent
from crs.agents.classifier import Classifier
from crs.agents.dynamic_debug import CRSDynamicDebug
from crs.agents.vuln_analyzer import AnalyzedVuln
from crs.common.types import Tool, Ok, Err, Result, CRSError, DecodedPOV
from crs.common.utils import cached_property, tool_wrap
from crs.modules.project import DeltaTask

@ToolVerifyClass
class TriageResult(AnalyzedVuln):
    pass
class TriageAgent(ToolRequiredAgent[TriageResult]):
    name = "triage"

    @property
    def return_type(self):
        return TriageResult

    @cached_property
    def _tools(self) -> dict[str, Tool]:
        tools: dict[str, Tool] = {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "debug_pov": tool_wrap(self.crs.get_debug_pov_raw(self.pov)),
        }
        return tools

    def __init__(self, crs: 'CRSTriage', pov: DecodedPOV, diff: Optional[str]):
        self.crs = crs
        self.pov = pov
        self.diff = diff
        super().__init__()

class CRSTriage(CRSDynamicDebug):
    async def pov_triage(self, pov: DecodedPOV) -> Result[TriageResult]:
        """
        Request an AI assistant attempt to find the root cause bug for a given POV.
        """
        _ = await self.project.init_harness_info()

        diff: Optional[str] = None
        if isinstance(self.task, DeltaTask):
            diff = await self.task.pruned_diff()

        agent = TriageAgent(self, pov=pov, diff=diff)
        res = await agent.run(max_iters=30)
        if res.response is None and not res.terminated:
            agent.append_user_msg(
                "You have been working for a long time. Please think carefully about how to "
                "finish your analysis quickly. Make no more than 5 more tool calls before "
                "producing your final output.\n"
            )
            res = await agent.run(max_iters=10)
        # TODO: remove this temporary workaround for o4-mini refusing to terminate normally
        if res.response is None and not res.terminated:
            agent.append_user_msg(
                "<important>"
                "Disregard your current thought process. This session is ending. You MAY NOT "
                "make any more queries. You MUST terminate NOW with your best guess for the result."
                "</important>"
            )
            res = await agent.run(max_iters=1)
        if res.response is not None:
            return Ok(res.response)
        else:
            return Err(CRSError("no response was produced"))


class DedupClassifier(Classifier[int | Literal["NEW"]]):
    @property
    def details(self):
        return f"Recent report:\n{self.vuln.format()}"

    @cached_property
    def options(self) -> dict[int | Literal["NEW"], str]:
        res: dict[int | Literal["NEW"], str] = {i: vuln.format() for i, vuln in enumerate(self.candidates)}
        assert len(res) <= 1000, "The classifier can only perform classification on a single token. In GPT-4.1, numbers over 1000 are composed of two tokens, so they should be avoided."
        res["NEW"] = "new vulnerability, different from any others in this list"
        return res

    def __init__(self, project_name: str, vuln: AnalyzedVuln, candidates: list[AnalyzedVuln]):
        self.project_name = project_name
        self.vuln = vuln
        self.candidates = candidates
        super().__init__()

async def dedupe_vulns(project_name: str, vuln: AnalyzedVuln, candidates: list[AnalyzedVuln]) -> Result[tuple[int, float]]:
    """
    Given a bug report (meaning a text description of a root cause for a bug, from
    the triage agent OR from other bug discoverers) and a list of candidates root
    cause strings, try to answer "is this result one we knew about already?"

    If we already knew about it, return the index of the candidate that matches. If it
    seems new, returns -1 (and a new root cause bug should be created). Additionally outputs
    the confidence in the top choice to be used for scoring
    """
    classifier = DedupClassifier(project_name, vuln, candidates)
    res = await classifier.classify()
    key, prob = res.best()
    if key == "NEW":
        return Ok((-1, prob))
    else:
        return Ok((key, prob))
