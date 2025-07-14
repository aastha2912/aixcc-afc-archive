from asyncio.subprocess import PIPE, STDOUT
from crs.common.aio import Path
from pydantic import BaseModel, ConfigDict
from typing import Optional
import asyncio
import orjson
import re

from crs import config
from crs.agents.func_summarizer import CRSFunctionSummarizer, Summary
from crs.agents.vuln_analyzer import CRSVuln
from crs.common import docker, process
from crs.common.types import Result, Ok, Err, CRSError, VulnReport
from crs.common.utils import requireable, require, gather_dict, trim_tool_output
from crs.modules import project

from crs_rust import logger


INFER_PATH = (config.CRSROOT / "../external/infer/")

INFER_DEFAULT_FIELD_DEPTH = 8
DEFAULT_MAX_STATIC_RESULTS = 75
INFER_KEEP_GOING_COUNT = 100

# this must take in a cwd, because the paths are relative to the CWD, not relative to /src/
def qualifier_name_loc(qualifier: str, cwd: Path):
    called_name, remainder = qualifier.split('`')[-2:]
    matched = re.findall(r"\((.*) : (\d+)\)", remainder)
    if len(matched) == 1:
        filename, line = matched[0]
        if (cwd / filename).is_relative_to("/src/"):
            filename = (cwd / filename).relative_to("/src/").as_posix()
            line = int(line)
        else:
            filename, line = None, None
    else:
        filename, line = None, None
    return called_name, filename, line

class InferBugReport(BaseModel):
    file: str
    line: int
    procedure: str
    bug_type_hum: str
    qualifier: str
    model_config = ConfigDict(extra="ignore") # Ignore any extra fields in the input dictionary

class StaticAnalyzer:
    def __init__(self, task: project.Task):
        self.task = task
        self.project = self.task.project

    @requireable
    async def run_infer(self) -> Result[list[InferBugReport]]:
        mounts: dict[Path, str] = {
            INFER_PATH : "/opt/infer/",
        }

        if self.project.info.language.lower() == "java":
            raise NotImplementedError
            ## modify the build.sh to use infer
            ## FIXME: needs to use docker.vread / vwrite to support remote docker
            # build_script = (tmp_src / "build.sh").read_text()
            # build_script = build_script.replace("javac", "/opt/infer/infer/bin/infer capture -- javac")
            # _ = await (tmp_src / "build.sh").write_text(build_script)

        else: # should just be c (maybe c++)
            # build with bear

            try:
                async with self.project.run_bear_docker(mounts=mounts) as wrun:
                    run = require(wrun)

                    async def step(cont: bool = False) -> process.Process:
                        cont_arg = ["--keep-going"] if cont else []
                        proc = await run.exec(
                            "/opt/infer/infer/bin/infer",
                            *cont_arg,
                            "--bufferoverrun",
                            "--bo-field-depth-limit", str(INFER_DEFAULT_FIELD_DEPTH),
                            "--no-filtering",
                            "--no-bo-assume-void",
                            "--compilation-database", "/src/compile_commands.json",
                            "-o", "/tmp/infer-out",
                            stdout=PIPE, stderr=STDOUT,
                        )
                        return proc

                    proc = await step(False)
                    output, _ = await proc.communicate()
                    if proc.returncode != 0:
                        logger.warning("Infer had an error, but we will try to continue")
                        for _ in range(INFER_KEEP_GOING_COUNT):
                            proc = await step(True)
                            output, _ = await proc.communicate()
                            if proc.returncode == 0:
                                break
                        else:
                            return Err(CRSError("Failed to run infer: " + trim_tool_output(output).decode(errors="replace")))

                    report_json = require(await docker.vread(run, "/tmp/infer-out/report.json"))
                    j = await asyncio.to_thread(orjson.loads, report_json)
                    return Ok([InferBugReport(**fields) for fields in j])
            except TimeoutError:
                return Err(CRSError("infer docker timed out"))


    @requireable
    async def filtered_infer_vulns(self) -> Result[list[InferBugReport]]:
        func_reports = require(await self.run_infer())
        repo_root = f"/src/{Path(self.project.info.main_repo).stem}"
        def in_scope(path: str):
            # relative to the project working_dir: that is in scope
            if not path.startswith("/"):
                return True
            # absolute path inside the repository: also in scope
            elif path.startswith(repo_root):
                return True
            # everything else: out of scope
            else:
                return False
        # extract only the bugs reported for in-scope files
        return Ok([r for r in func_reports if in_scope(r.file)])

    @requireable
    async def get_func_summaries(self, func_reports: list[InferBugReport]) -> Result[dict[str, Summary]]:
        cwd = Path(require(await self.project.get_working_dir()))
        sketch_funcs = {qualifier_name_loc(x.qualifier, cwd) for x in func_reports if 'by call to' in x.qualifier}

        summarizer = CRSFunctionSummarizer.from_task(self.task)
        summaries: dict[str, Summary] = dict()

        async def get_summary_with_alts(f: str, fname: Optional[str], line: Optional[int]):
            match await summarizer.summarize_func(f, func_path=fname):
                case Ok(summary):
                    summaries[f] = summary
                case Err(e):
                    logger.warning(f"summary failed for {f} : {e}")

        _ = await gather_dict({f: get_summary_with_alts(*f) for f in sketch_funcs})

        return Ok(summaries)

    async def _create_infer_vuln_report(
        self,
        func_report: InferBugReport,
        summaries: dict[str, Summary]
    ) -> Optional[VulnReport]:
        note: Optional[str] = None
        if 'by call to' in func_report.qualifier:
            called_name = func_report.qualifier.split('`')[-2]
            summary_info = summaries.get(called_name)
            if summary_info is None or summary_info.always_safe:
                return None # no vuln here
            note = f"{called_name} safety requirements : {summary_info.summary}"

        procedure = func_report.procedure
        base_dir = None
        match await self.project.get_working_dir():
            case Ok(working_dir):
                base_dir = Path(working_dir).relative_to("/src")
            case Err(e):
                logger.error(f"failed to get working dir for task {self.task.task_id} : {e}")
                return None

        bug_type = func_report.bug_type_hum
        bug_type = re.sub(" L[12345]", "", bug_type)
        bug_type = bug_type.replace(" S2", "").replace(" U5", "")
        qualifier = (func_report.qualifier
                .replace("+oo", "+inf").replace("-oo", "-inf")
                .replace("Size: ", "Buffer Size: ").replace("Offset: ", "Accessed Offset: ")
                .strip("."))
        qualifier = re.sub(r"(.* call to `.*` )(\(.*\))", r"\1", qualifier).rstrip()
        desc = (
            f"Vulnerability site: {procedure} on line {func_report.line}\n"
            f"Vulnerability type: {bug_type}\n"
            f"Qualifier: {qualifier}"
        )
        if note:
            desc += f"\nNote: {note}"

        return VulnReport(
            task_uuid=self.task.task_id,
            project_name=self.project.name,
            function=procedure,
            file=(base_dir / func_report.file).as_posix(),
            description=desc,
        )

    @requireable
    async def _create_infer_vuln_reports(
        self,
        func_reports: list[InferBugReport]
    ) -> Result[list[VulnReport]]:
        summaries = require(await self.get_func_summaries(func_reports))
        return Ok([
            vuln_report for r in func_reports
            if (vuln_report := await self._create_infer_vuln_report(r, summaries)) is not None
        ])

    @requireable
    async def get_infer_vuln_reports(self) -> Result[list[VulnReport]]:
        # TODO: add storage / caching of infer results
        func_reports = require(await self.filtered_infer_vulns())
        return await self._create_infer_vuln_reports(func_reports)

    async def analyze_func(
        self,
        func_report: InferBugReport,
        summaries: dict[str, Summary]
    ) -> float:
        report = await self._create_infer_vuln_report(func_report, summaries)
        if report is None:
            return 0
        match await CRSVuln.from_task(self.task).score_vuln_report(report):
            case Ok(score):
                return score.overall()
            case Err(e):
                logger.error(f"Error scoring infer vuln report: {repr(e)}")
                return 0

    @requireable
    async def score_vuln_sites(self) -> Result[tuple[list[float], list[InferBugReport], dict[str, Summary]]]:
        func_reports = require(await self.filtered_infer_vulns())
        # projects may pull down several repositories that infer analyzes. We only want reports about
        # OUR repository. (ex: curl uses openssl. We do not want to waste time analyzing out of scope openssl bugs)
        summaries = require(await self.get_func_summaries(func_reports))
        scores = await asyncio.gather(*[self.analyze_func(r, summaries) for r in func_reports])
        return Ok((scores, func_reports, summaries))

    @requireable
    async def get_vuln_sites(self, n: int = DEFAULT_MAX_STATIC_RESULTS) -> Result[list[InferBugReport]]:
        scores, report, _ = require(await self.score_vuln_sites())
        return Ok([r for r, _ in sorted(zip(report, scores), key=lambda s: s[1], reverse=True)[:n]])
