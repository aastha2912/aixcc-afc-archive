from crs.common.aio import Path
from pydantic import BaseModel, Field
from typing import Optional

from opentelemetry import trace

from crs import config
from crs.agents.tool_required_agent import ToolRequiredAgent, ToolVerifyClass
from crs.common.constants import C_EXTENSIONS, JAVA_EXTENSIONS
from crs.common.types import Message, Tool, ToolError, ToolResult, CRSError, Ok, Err, Result, PatchArtifact, DecodedPOV, AnalyzedVuln
from crs.common.oneshot import summarize_build_failure, summarize_test_failure
from crs.common.utils import cached_property, require, requireable, tool_wrap, trim_tool_output
from crs.modules.project import BuildError, NoTests
from crs.modules.source_editor import Editor
from crs.agents.source_questions import CRSSourceQuestions, SourceQuestionsResult
from crs.agents.pov_producer import CRSPovProducer

from crs_rust import logger

PATCH_FUNC_FAILURE = "The PoVs no longer triggered a sanitizer, but the functionality tests failed"
PATCH_SEC_FAILURE = "A PoV still triggered a sanitizer"

MAX_POV_HINTS = 3

@ToolVerifyClass
class PatchResult(BaseModel):
    success: bool = Field(description="Whether you succeeded to patch the vulnerability.")
    failure_reason: Optional[str] = Field(default=None, description="If you failed to produce a PoV, provide a brief summary of why. You may not give up without testing some POVs first.")

class ConfirmedPatchResult(PatchResult):
    patch: str
    tested_povs: list[DecodedPOV]
    build_artifacts: list[PatchArtifact]

class PatcherAgent(ToolRequiredAgent[PatchResult]):
    name = "patcher"

    @property
    def return_type(self):
        return PatchResult

    @requireable
    async def test_patch(self) -> Result[str]:
        match await self.crs.project.build_all(capture_output=True):
            case Err(BuildError(error=error)):
                match await summarize_build_failure(error):
                    case Err(CRSError(error=error)):
                        pass
                    case Ok(error):
                        pass
            case Err(CRSError(error=error)):
                pass
            case Ok(_):
                error = None
        if error is not None:
            return Err(CRSError(
                "the code failed to build",
                extra={
                    "build_error": trim_tool_output(error),
                    "suggestion": "You may want to undo some edits before proceeding with the `undo_last_patch` tool",
                    "status": f"Currently there are {self.crs.project.editor.patch_num} edits"
                }
            ))

        ran_tests = False
        match await self.crs.project.run_tests():
            case Ok(None):
                ran_tests = True
                pass
            case Err(NoTests()):
                logger.warning("No functionality tests available, skipping test phase")
            case Err(CRSError() as e):
                logger.warning(f"functionality tests failed: {repr(e)}")
                if e.extra and "output" in e.extra and isinstance(e.extra["output"], str):
                    match await summarize_test_failure(e.extra["output"]):
                        case Err(CRSError(error=error)):
                            # summarization failed, log a warning and settle for just trimming the output
                            logger.warning(f"summarize_test_failure failed: {error}")
                            e.extra["output"] = trim_tool_output(e.extra["output"])
                        case Ok(summary):
                            e.extra["output"] = summary
                return Err(e)

        # check that it fixes known povs for the commit
        harnesses = require(await self.crs.project.init_harness_info())
        for pov in self.povs:
            harness = [x for x in harnesses if x.name == pov.harness]
            if len(harness) != 1:
                logger.error(f"failed to get harness for name {pov.harness}: {harnesses}")
            match await self.crs.project.test_pov_contents(harness[0], pov.input):
                case Ok(_):
                    return Err(CRSError(PATCH_SEC_FAILURE))
                case _:
                    pass

        result = "The patched code built successfully.\n"
        if self.povs:
            result += "The known PoVs no longer reproduce.\n"
        else:
            result += (
                "We had no available PoVs to test this patch, so we are unsure if the patch fixes the root cause. "
                "Please carefully consider if it's still possible to trigger a runtime safety issue for this vulnerability. "
                "If you believe the code is now safe, please terminate this patching session. "
                "Otherwise, it's not too late to make more changes.\n"
            )
        if ran_tests:
            result += "The functionality tests passed.\n"
        else:
            result += (
                "There were no functionality tests available, so we are unsure if the patch breaks functionality. "
                "Please carefully consdier if the patch preserves all intended functionality. "
                "If you believe the patch addressed the vulnerability without breaking intended functionality, "
                "please terminate this session. Otherwise, it's not too late to make more changes.\n"
            )
        return Ok(result)

    async def sanity_patch_hook[R](self, path: str, patch: str) -> Optional[ToolResult[Editor.Note]]:
        if self.crs.project.info.language == "jvm":
            extensions = JAVA_EXTENSIONS
            lang = "Java"
        else:
            extensions = C_EXTENSIONS
            lang = "C"
        if Path(path).suffix not in extensions:
            return ToolError(f"{path} is not a valid {lang} file", extra={"allowed extensions": " ".join(sorted(extensions))})

        match await self.crs.project.init_harness_info():
            case Ok(harnesses):
                pass
            case Err():
                logger.error("no harnesses when trying to patch?")
                return # shouldn't happen
        for harness in harnesses:
            if Path(harness.source) == Path(path):
                return ToolError(f"{path} is a fuzzer harness file. Patching fuzzer harness files is prohibited.")

    async def test_patch_hook[R](self, res: ToolResult[R]):
        if not isinstance(res, ToolError):
            patch = await self.crs.project.editor.get_repo_diff(self.repo_base.as_posix())
            # build already done so should be cached
            build_artifacts: list[PatchArtifact] = []
            for config in self.crs.project.info.build_configs:
                tar_path = await self.crs.project.get_build_tar(config)
                build_artifacts.append(PatchArtifact(build_tar_path=tar_path.as_posix(), build_config=config))
            self.patch = ConfirmedPatchResult(
                success=True,
                patch=patch,
                tested_povs=self.povs,
                build_artifacts=build_artifacts,
            )
        elif res.error in {PATCH_FUNC_FAILURE, PATCH_SEC_FAILURE}:
            test_type = {PATCH_FUNC_FAILURE: "functionality", PATCH_SEC_FAILURE: "security"}[res.error]

            intervene = False
            if test_type == "functionality":
                self.func_failure_count += 1
                intervene = (self.func_failure_count % 4 == 0)
            else:
                self.sec_failure_count += 1
                intervene = (self.sec_failure_count % 4 == 0)
            if intervene:
                logger.info("intervening with some advice due to persistent patch failure")
                res.action.append = [Message(
                    role="user",
                    content=(
                        f"Your {test_type} tests failed again. Please consider an alternate "
                        "approach to patching the vulnerability that you can take. Try to come "
                        "up with 3 ideas to patch, and then choose the one that seems the best."
                    )
                )]
        return res

    async def source_code_questions(self, question: str, additional_info: str = "") -> Result[SourceQuestionsResult]:
        return await self.crs.source_code_questions(question, additional_info, self.rawdiff)

    @cached_property
    def _tools(self) -> dict[str, Tool]:
        return {
            "source_questions": tool_wrap(self.source_code_questions),
            "read_definition": tool_wrap(self.crs.searcher.read_definition),
            "read_source": tool_wrap(self.crs.searcher.read_source),
            "find_references": tool_wrap(self.crs.searcher.find_references),
            "apply_patch": tool_wrap(self.crs.project.editor.apply_patch, pre_hooks=[self.sanity_patch_hook]),
            "undo_last_patch": tool_wrap(self.crs.project.editor.undo_last_patch),
            "list_current_edits": tool_wrap(self.crs.project.editor.list_edits),
            "test_patch": tool_wrap(self.test_patch, post_hooks=[self.test_patch_hook]),
        }

    def __init__(self, crs: 'CRSPatcher', vuln: AnalyzedVuln, diff: Optional[str], povs: list[DecodedPOV], repo_base: Path, rawdiff: bool = False):
        self.MAX_POV_HINTS = MAX_POV_HINTS
        self.crs = crs
        self.vuln = vuln
        self.diff = diff
        self.povs = sorted(povs, key=lambda pov: (pov.python is None, len(pov.input)))
        self.repo_base = repo_base
        self.func_failure_count = 0
        self.sec_failure_count = 0
        self.patch: Optional[ConfirmedPatchResult] = None
        self.rawdiff = rawdiff
        super().__init__()

class CRSPatcher(CRSPovProducer, CRSSourceQuestions):
    @config.telem_tracer.start_as_current_span(
        "patch_vulnerability",
        attributes={"crs.action.category": "patch_generation", "crs.action.name": "patch_vulnerability"},
        record_exception=False,
    )
    @requireable
    async def patch_vulnerability(self, vuln: AnalyzedVuln, povs: list[DecodedPOV], rawdiff: bool = False) -> Result[PatchResult]:
        """
        Spawns an agent to try patching a vulnerability. Any povs provided in `povs` are
        tested.
        Argument `rawdiff` is set to True if and only if the vulnerability is found using rawdiff
        of a DeltaTask.
        """
        fork = self.new_fork()
        diff = (await self.read_diff(rawdiff=rawdiff)).unwrap_or(None)
        repo_base = require(await self.project.repo_path())
        agent = PatcherAgent(fork, vuln, diff, povs, repo_base, rawdiff)
        _ = await agent.run()
        match agent.patch:
            case ConfirmedPatchResult() as r:
                response = r
            case None:
                response = PatchResult(success=False, failure_reason="the agent did not produce a result")

        span = trace.get_current_span()
        span.add_event(
            f"patch producer complete",
            attributes={"crs.debug.success": response.success}
        )
        return Ok(response)
