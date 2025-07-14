import asyncio
import re
from typing import Optional, Literal

from pydantic import BaseModel, Field

from crs.agents.classifier import Classifier
from crs.agents.pov_producer import CRSPovProducerBufGen, HarnessInputEncoderResult
from crs.agents.xml_agent import XMLAgent, XMLVerifyClass
from crs.common.types import DecodedPOV, Err, Ok, Result, Message, Tool, ToolError, ToolResult, ToolSuccess
from crs.common.utils import (
    cached_property,
    require,
    requireable,
    tool_wrap,
)
from crs.modules.coverage import CoverageAnalyzer, Frontier
from crs.modules.project import Project, Harness
from crs.modules.search_code import Searcher

from crs_rust import logger

# after a branch site is first unearthed and sent to us, we should wait a while:
# the fuzzer made progress to unearth us, so it may soon make enough progress to flip this too
BRANCH_FLIP_DELAY = 20 * 60

# don't try to flip a branch that is below this scoring threshold
BRANCH_FLIP_SCORE = 0.6


class LikelyFlippableClassifier(Classifier[Literal['likely', 'unlikely']]):
    @property
    def details(self) -> str:
        return (
            f"Fuzzing Harness Name: {self.harness_name}\n"
            f"Target function: {self.target_function}\n"
            f"Reached function:\n```\n{self.reached_code}\n```"
        )

    @cached_property
    def options(self) -> dict[Literal['likely', 'unlikely'], str]:
        return {
            "likely": f"A change in user input can likely trigger a call to the target function",
            "unlikely": f"The target function requires non user-controllable data to reach",
        }

    def __init__(self, project_name: str, lang: str, harness_name: str, target_function: str, reached_code: str):
        self.project_name = project_name
        self.lang = lang
        self.harness_name = harness_name
        self.target_function = target_function
        self.reached_code = reached_code
        super().__init__()

async def should_try_branch(project: Project, harness: Harness, target_function: str, reached_code: str) -> bool:
    score = (await LikelyFlippableClassifier(
        project.name,
        "Java" if project.info.language == "jvm" else "C",
        harness.name,
        target_function,
        reached_code,
    ).classify()).get("likely", 0)

    logger.info("preflip {target_func} score = {score}", target_func=target_function, score=score)
    return score > BRANCH_FLIP_SCORE


@XMLVerifyClass
class BranchFlipperResult(BaseModel):
    summary: str = Field(description="A brief summary of your work.")
    input_python: str = Field(
        description="The python to generate the input seed that reaches the target."
    )
    reach_target_function: bool = Field(
        description="Whether the seed was tested to successfully reach the target function."
    )


class ConfirmedBranchFlipperResult(BranchFlipperResult):
    line_hit: int


class BranchFlipperAgent(XMLAgent[BranchFlipperResult]):
    name = "branch_flipper"

    @property
    def return_type(self):
        return BranchFlipperResult

    async def coverage_hook[**P](
        self,
        res: ToolResult[CoverageAnalyzer.LineCoverageInfo],
        input_python: str,
        target_file: str,
        target_line: int,
        *args: P.args,
        **kwargs: P.kwargs,
    ):
        # check only the same file
        if target_file != self.target_file:
            return res

        # post fetching
        match await self.crs.searcher.read_definition(self.target_function, self.target_file):
            case Ok(defn):
                self.target_source = defn
            case Err(err):
                logger.debug(f"failed to get target source while fetching; {err.error}")
                return res

        # is the target function hits.
        hits: list[int] = []
        match res:
            case ToolSuccess():
                if res.result["line_reached"]:
                    hits.append(target_line)
                else:
                    hits.extend([
                        int(i)
                        for i in re.findall(
                            r"The nearest .+? reached line was .+?:(\d+?)",
                            res.result["response"]
                        )
                    ])
            case ToolError():
                pass

        for line in hits:
            if self.target_source["line_start"] <= line < self.target_source["line_end"]:
                res.action.stop = True
                logger.info(f"branch flipper flipped to reach {self.target_file}:{self.target_function}")
                self.result = ConfirmedBranchFlipperResult(
                    summary="the target funtion reached, the agent stopped by the `coverage_hook`",
                    input_python=input_python,
                    reach_target_function=True,
                    line_hit=target_line,
                )
                break
        return res

    @cached_property
    def tools(self) -> dict[str, Tool]:
        tools: dict[str, Tool] = {
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "query_coverage": tool_wrap(self.query_coverage, post_hooks=[self.coverage_hook]),
            #"debug_pov": tool_wrap(self.crs.debug_pov),
        }
        return tools

    async def build_pov(self, input_python: str) -> Result[bytes]:
        return await self.crs.project.build_pov(input_python)

    @requireable
    async def query_coverage(
        self, input_python: str, target_file: str, target_line: int
    ):
        pov = require(await self.build_pov(input_python))
        return await self.crs.coverage.query_coverage_raw(
            self.harness_num, pov, target_file, target_line
        )

    def get_result(self, msg: Message) -> BranchFlipperResult | Message | None:
        if self.result is not None:
            return self.result
        return super().get_result(msg)

    def __init__(
        self,
        crs: "CRSBranchFlipper",
        harness_num: int,
        harness: Harness,
        seed: DecodedPOV,
        target_file: str,
        target_function: str,
        reached_file: str,
        reached_function: str,
        tips: str = "",
        input_encoder: HarnessInputEncoderResult | None = None,
        target_source: Searcher.FileSourceContents | None = None,
        reached_source: Searcher.FileSourceContents | None = None,
    ):
        self.crs = crs
        self.harness_num = harness_num
        self.harness = harness
        self.seed = seed
        self.target_file = target_file
        self.target_function = target_function
        self.reached_file = reached_file
        self.reached_function = reached_function
        # additional materials
        self.tips = tips
        self.input_encoder = input_encoder
        self.target_source = target_source
        self.reached_source = reached_source
        self.result: Optional[ConfirmedBranchFlipperResult] = None
        super().__init__()


class CRSBranchFlipper(CRSPovProducerBufGen):
    async def encoder_hook(self, harness_num: int) -> Optional[ToolResult[HarnessInputEncoderResult]]:
        """
        Called when asked to generate a harness input encoder for {harness_num}.
        If it returns non-None, the real tool call is skipped.
        May be overridden by child classes.
        """
        return None

    @requireable
    async def try_reach_raw(
        self,
        seed: DecodedPOV,
        encoder: HarnessInputEncoderResult,
        harness_num: int,
        target_file: str,
        target_function: str,
        reached_file: str,
        reached_function: str,
    ):
        harnesses = require(await self.project.init_harness_info())
        if len(harnesses) == 1 and harness_num != 0:
            harness_num = 0

        harness = require(self.project.check_harness(harness_num))
        tips = await self.harness_tips(harness)

        agent = BranchFlipperAgent(
            self,
            harness_num,
            harness,
            seed,
            target_file,
            target_function,
            reached_file,
            reached_function,
            # additional materials
            tips=tips,
            reached_source=require(await self.searcher.read_definition(reached_function, reached_file)),
            input_encoder=encoder,
        )
        response = (await agent.run()).response
        match response:
            case ConfirmedBranchFlipperResult(line_hit=True):
                pass
            case BranchFlipperResult(line_hit=True):
                response = BranchFlipperResult(
                    summary=f"The agent thought it succeeded; following is the agent's summary:{response.summary}",
                    input_python=response.input_python,
                    reach_target_function=True,
                )
            case BranchFlipperResult(line_hit=False):
                response = BranchFlipperResult(
                    summary=f"The agent did not reach the target function; following is the agent's summary:\n\n{response.summary}",
                    input_python=response.input_python,
                    reach_target_function=False,
                )
            case None:
                logger.error(f"no result from {agent.id}")
                response = BranchFlipperResult(
                    summary=f"The agent did not reach the target function",
                    input_python="",
                    reach_target_function=False,
                )
            case _:
                pass
        return Ok(response)

@requireable
async def pre_flip_branch(project: Project, cov: CoverageAnalyzer, frontier: Frontier, age: float) -> Result[bool]:
    # step 1: check if this is still relevant after a delay
    await asyncio.sleep(BRANCH_FLIP_DELAY - age)

    target_file, start, _, target_func = frontier.target.split(":", maxsplit=3)

    direct_hits, _ = require(
        await cov.query_statically_reachable(target_file, int(start))
    )
    if direct_hits:
        # we've already hit this function! don't bother
        logger.info("preflip {target_file}:{target_func} hit1", target_file=target_file, target_func=target_func)
        return Ok(False)

    # sometimes statically reachable also LIES about the target function. For example:
    # it may report the location as a header file declaration vs the actual definition.
    # Let's double check that we haven't hit this
    tree = (await project.vfs.tree()).unwrap_or(None)
    match await project.searcher.find_definition(target_func):
        case Ok([defsite]):
            for site in defsite.defs:
                if tree:
                    filename = (tree.normalize_path(defsite.file_name)).unwrap_or(defsite.file_name)
                else:
                    filename = defsite.file_name
                match await cov.query_statically_reachable(filename, site.line):
                    case Ok((direct_hits, _)):
                        if direct_hits:
                            # we've already hit this function! don't bother
                            logger.info("preflip {target_file}:{target_func} hit2", target_file=target_file, target_func=target_func)
                            return Ok(False)
                    case _:
                        pass
        case _:
            # we can't find it, or there are more than one definition so this is tough. Let's proceed
            pass

    # step 2: classify whether this is plausible to flip
    harnesses = require(await project.init_harness_info())

    reached_file, _, _, reached_func = frontier.closest.split(":", maxsplit=3)
    reached_src = require(await project.searcher.read_definition(reached_func, reached_file, display_lines=False))
    return Ok(
        await should_try_branch(project, harnesses[frontier.harness_num], target_func, reached_src["contents"])
    )
