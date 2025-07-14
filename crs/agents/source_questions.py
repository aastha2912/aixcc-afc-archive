from pydantic import BaseModel, Field
from typing import Optional

from crs.agents.tool_required_agent import ToolVerifyClass, ToolRequiredAgent
from crs.agents.crsbase import CRSBase
from crs.common.types import Tool, Ok, Err, Result, CRSError
from crs.common.utils import cached_property, tool_wrap
from crs.modules.project import DeltaTask

@ToolVerifyClass
class SourceQuestionsResult(BaseModel):
    answer: str = Field(description="the answer to the question")

class SourceQuestionsAgent(ToolRequiredAgent[SourceQuestionsResult]):
    name = "source_questions"

    @property
    def return_type(self):
        return SourceQuestionsResult

    async def read_diff(self) -> Result[str]:
        return await self.crs.read_diff(self.rawdiff)

    @cached_property
    def _tools(self) -> dict[str, Tool]:
        tools: dict[str, Tool] = {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
        }
        if isinstance(self.crs.task, DeltaTask):
            tools["read_diff"] = tool_wrap(self.read_diff)
        return tools

    def __init__(self, crs: 'CRSSourceQuestions', question: str, additional_info: str, harness: Optional[str] = None, rawdiff: bool = False):
        self.crs = crs
        self.question = question
        self.additional_info = additional_info
        self.harness = harness
        self.rawdiff = rawdiff
        super().__init__()

class CRSSourceQuestions(CRSBase):
    async def read_diff(self, rawdiff: bool = False) -> Result[str]:
        """
        Returns the diff of the source code change which is currently being examined.
        """
        if isinstance(self.task, DeltaTask):
            return Ok(await self.task.pruned_diff(rawdiff=rawdiff))
        else:
            return Err(CRSError("Current task has no associated diff"))

    async def source_code_questions(self, question: str, additional_info: str, rawdiff: bool = False) -> Result[SourceQuestionsResult]:
        agent = SourceQuestionsAgent(self, question=question, additional_info=additional_info, rawdiff=rawdiff)
        return await self._source_questions_inner(agent)

    def source_code_questions_for_harness(self, harness: str):
        async def source_code_questions(question: str, additional_info: str) -> Result[SourceQuestionsResult]:
            agent = SourceQuestionsAgent(self, question=question, additional_info=additional_info, harness=harness)
            return await self._source_questions_inner(agent)
        return source_code_questions

    async def _source_questions_inner(self, agent: SourceQuestionsAgent) -> Result[SourceQuestionsResult]:
        _ = await self.project.init_harness_info()
        res = await agent.run()
        turn_limit_flag = False

        if not res.terminated and res.response is None:
            turn_limit_flag = True
            prompt = (
                "Please provide a final answer to the question based on the information you have collected so far.\n\n"
                "Include the following elements in your response:\n"
                "1. Specific facts you have discovered about the original question\n"
                "2. Concrete location information such as file paths, function names, and line numbers\n"
                "3. Code patterns, conditional statements, call relationships, etc. that you found\n"
                "4. If there are areas that need further investigation, specify what they are\n"
                "5. Additional insights or precautions that would be helpful to the questioner\n\n"
                "<IMPORTANT>\n"
                "Please provide an answer by synthesizing the investigation results so far. "
                "YOU MUST USE THE 'terminate' TOOL. Never call any other tools and only use the 'terminate' tool.\n"
                "</IMPORTANT>"
            )
            agent.append_user_msg(prompt)
            res = await agent.run(max_iters=1)

        if res.response is not None:
            if turn_limit_flag:
                res.response.answer = "<INFO>This answer is based on currently available information. Some areas may require additional investigation.</INFO>\n" + res.response.answer
            return Ok(res.response)
        else:
            return Err(CRSError("no response was produced"))
