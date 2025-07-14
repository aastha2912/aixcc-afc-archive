from dataclasses import dataclass
from opentelemetry import trace
from pydantic import BaseModel, Field, model_validator
from typing import Optional, Literal, Self

from crs import config
from crs.agents.crsbase import CRSBase
from crs.agents.classifier import Classifier, ClassifierBatchResult
from crs.agents.agent import CRSAgent
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass

from crs.common.types import Tool, Result, Ok, Err, CRSError, VulnReport, AnalyzedVuln
from crs.common.utils import cached_property, tool_wrap, require, requireable

from crs_rust import logger

DEFAULT_BATCH_SIZE = 2

class LikelyVulnClassifier(Classifier[Literal['likely', 'unlikely']]):
    @property
    def details(self):
        return f'Report: {self.report}\nFull Code:\n```\n{self.code}\n```'

    @cached_property
    def options(self) -> dict[Literal['likely', 'unlikely'], str]:
        return {
            "likely": f"The reported vuln can likely be triggered via user input",
            "unlikely": f"The reported vuln can not likely be triggered via user input",
        }

    def __init__(self, project_name: str, report: str, code: str):
        self.project_name = project_name
        self.report = report
        self.code = code
        super().__init__()

MIN_CONFIDENCE = 2

@XMLVerifyClass
class VulnAnalysis(BaseModel):
    triggerable: bool
    positive: Optional[AnalyzedVuln] = Field(default=None, description=(
        "if triggerable=true, provide this helpful information about the vulnerability"
    ))
    negative: Optional[str] = Field(default=None, description=(
        "if triggerable=false, provide a brief description of why the vulnerability is not triggerable"
    ))

    @model_validator(mode='after')
    def check_triggerable_positive_negative(self) -> Self:
        if self.triggerable:
            if self.positive is None:
                raise ValueError("If triggerable is True, positive must not be None.")
        else:
            if self.negative is None:
                raise ValueError("If triggerable is False, negative must not be None.")
        return self


class CRSVulnAnalyzerAgent(CRSAgent[VulnAnalysis, 'CRSVuln'], XMLAgent[VulnAnalysis]):
    name = "vuln_analyzer"

    @property
    def return_type(self) -> type[VulnAnalysis]:
        return VulnAnalysis

    @cached_property
    def tools(self) -> dict[str, Tool]:
        return {
            "list_definitions": tool_wrap(self.crs.searcher.list_definitions),
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references":  tool_wrap(self.crs.searcher.find_references),
        }

    def __init__(self, crs: 'CRSVuln', report: VulnReport):
        self.report = report
        super().__init__(crs)

@dataclass
class VulnScoreResult():
    result: ClassifierBatchResult[Literal['likely', 'unlikely']]

    def overall(self) -> float:
        return (self.result.max("likely"))

class CRSVuln(CRSBase):
    @requireable
    async def score_vuln_report(self, report: VulnReport, batch_size: int = DEFAULT_BATCH_SIZE) -> Result[VulnScoreResult]:
        """
        Use this function to get a probability score a candidate report.
        Internally, it uses an LLM classifier to estimate the probability of being a real vuln
        """

        match await self.project.searcher.read_definition(report.function, report.file):
            case Ok(res):
                code = res["contents"]
            # check if we can fallback to using definition range
            case Err(e) if report.function_range is not None:
                logger.warning(f"error reading definition: {repr(e)}")
                start, end = report.function_range
                res = require(await self.project.searcher.read_source_range(report.file, max(1, start-1), end+1, display_lines=True))
                code = res["contents"]
            case Err(e):
                logger.error(f"error reading definition: {repr(e)} - no range provided, so giving up")
                return Err(e)
        batch = await LikelyVulnClassifier.batch_classify(batch_size, self.project.name, report.description, code)
        return Ok(VulnScoreResult(result=batch))

    @requireable
    async def analyze_vuln_report(self, report: VulnReport, model_idx: int = 0) -> Result[VulnAnalysis]:
        """
        Use this function to analyze a potential vulnerability in this task. This analysis
        is somewhat expensive but is good at noticing false positives, so it suitable
        as a final filtering step before attempting POV production.

        Returns
        -------
        dict
            the results, or any errors
        """
        _ = require(await self.project.init_harness_info())
        with config.telem_tracer.start_as_current_span(
            "analyze_vuln",
            attributes={
                "crs.action.name": "analyze_vuln_report", "crs.action.category": "static_analysis",
            },
            record_exception=False
        ) as span:
            agent = CRSVulnAnalyzerAgent(crs=self, report=report)
            agent.model_idx = model_idx
            res = await agent.run(max_iters=30)
            if res.response is None and not res.terminated:
                agent.append_user_msg(
                    "You have been working for a long time. Please think carefully about how to "
                    "finish your analysis quickly. Make no more than 3 more tool calls before "
                    "producing your final output."
                )
                res = await agent.run(max_iters=10)
            # TODO: remove this temporary workaround for o4-mini refusing to terminate normally
            if res.response is None and not res.terminated:
                agent.append_user_msg(
                    "<important>"
                    "Disregard your current thought process. This session is ending. You MAY NOT "
                    "make any more queries. You MUST terminate NOW with your best guess for the result. "
                    "</important>"
                )
                res = await agent.run(max_iters=1)

            response = res.response
            span = trace.get_current_span()
            if response is not None:
                span.add_event(
                    f"vuln analysis complete",
                    attributes={"crs.debug.analyzer.triggerable": response.triggerable}
                )
                return Ok(response)
            return Err(CRSError("no report info returned"))