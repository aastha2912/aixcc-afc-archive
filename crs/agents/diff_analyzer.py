from pydantic import BaseModel, Field
from typing import Optional

from opentelemetry import trace

from crs import config
from crs.agents.crsbase import CRSBase
from crs.agents.agent import CRSAgent
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass
from crs.agents.vuln_analyzer import AnalyzedVuln
from crs.common.types import Ok, Err, Result, Tool, CRSError
from crs.common.utils import cached_property, tool_wrap
from crs.modules.project import DeltaTask
from crs_rust import logger


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
        # (aastham) Add error handling for VFS operations that can fail with TaskGroup exceptions
        async def safe_read_definition(name: str, path: Optional[str] = None, line_number: Optional[int] = None, display_lines: bool = True):
            try:
                return await self.crs.searcher.read_definition(name, path, line_number, display_lines)
            except Exception as e:
                logger.warning(f"CRSDiffAgent: read_definition failed for {name}: {e}")
                return Err(CRSError(f"Failed to read definition: {e}"))
        
        async def safe_read_source(file_name: str, line_number: int):
            try:
                return await self.crs.searcher.read_source(file_name, line_number)
            except Exception as e:
                logger.warning(f"CRSDiffAgent: read_source failed for {file_name}:{line_number}: {e}")
                return Err(CRSError(f"Failed to read source: {e}"))
        
        async def safe_find_references(name: str, path: Optional[str] = None, case_insensitive: bool = False):
            try:
                return await self.crs.searcher.find_references(name, path, case_insensitive)
            except Exception as e:
                logger.warning(f"CRSDiffAgent: find_references failed for {name}: {e}")
                return Err(CRSError(f"Failed to find references: {e}"))
        
        return {
            "read_definition": tool_wrap(safe_read_definition),
            "read_source": tool_wrap(safe_read_source),
            "find_references": tool_wrap(safe_find_references),
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

        try:
            pruned_diff = await self.task.pruned_diff(rawdiff=rawdiff)
            logger.info(f"CRSDiff: Got pruned diff of size {len(pruned_diff)} for task {self.task.task_id}")
            # (aastham) Debug: Show first 500 chars of diff to see what we're analyzing
            logger.info(f"CRSDiff: Diff preview: {pruned_diff[:500]}...")
        except Exception as e:
            logger.error(f"CRSDiff: Failed to get pruned diff for task {self.task.task_id}: {e}")
            return Err(CRSError(f"failed to get pruned diff: {e}"))

        with config.telem_tracer.start_as_current_span(
            "analyze_diff",
            attributes={
                "crs.action.name": "analyze_diff", "crs.action.category": "static_analysis",
                "crs.debug.pruned_diff_size": len(pruned_diff), "crs.debug.raw_diff_size": len(self.task.diff),
            },
            record_exception=False,
        ) as span:
            try:
                agent = CRSDiffAgent(crs=self, diff=pruned_diff)
                logger.info(f"CRSDiff: Starting agent analysis for task {self.task.task_id}")
                agent_result = await agent.run()
                res = agent_result.response
                logger.info(f"CRSDiff: Agent completed for task {self.task.task_id}, found {len(res.vuln) if res else 0} vulnerabilities")
                # (aastham) Debug: Show what the agent actually returned
                if res:
                    logger.info(f"CRSDiff: Agent response - change_desc: {res.change_desc[:200]}...")
                    if res.vuln:
                        logger.info(f"CRSDiff: Found vulnerabilities: {[v.description[:100] for v in res.vuln]}")
                else:
                    logger.warning(f"CRSDiff: Agent returned None response for task {self.task.task_id}")
            except Exception as e:
                logger.error(f"CRSDiff: Agent failed for task {self.task.task_id}: {e}")
                return Err(CRSError(f"agent failed: {e}"))

            span = trace.get_current_span()
            if res is not None:
                span.add_event(
                    f"diff analysis complete",
                    attributes={"crs.debug.analyzer.vulns_found": len(res.vuln)}
                )
                return Ok(res)
            logger.error(f"CRSDiff: No response from agent for task {self.task.task_id}")
            return Err(CRSError("no diff info returned"))
