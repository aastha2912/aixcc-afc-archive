import asyncio
import orjson

from crs import config
from crs.modules.project import Task
from crs.common.types import VulnReport, Result, Ok
from crs.common.utils import require, requireable

from .vfs_loader import load_vfs
from .full import analyze_project, analyze_project_multifunc

from .data import AnalysisProject, AnnotatedReport

from crs_rust import logger

def to_vuln_report(task: Task, report: AnnotatedReport, vuln: str):
    member = report.member
    a, b = member.file.range_to_lines(member.range)
    return VulnReport(
        task_uuid=task.task_id,
        project_name=task.project.name,
        function=member.name.decode(),
        file=member.file.path,
        description=vuln,
        function_range=(a + 1, b + 1),
    )

@requireable
async def get_ainalysis_reports(task: Task, model: str, multi: bool = False) -> Result[list[VulnReport]]:
    project = task.project
    repo_path = require(await project.repo_path())
    aproject: AnalysisProject = require(await load_vfs(project.vfs, repo_path, language=project.info.language))
    aproject.build_lut()

    if multi:
        llm_queries, reports = await analyze_project_multifunc(aproject, model=model)
    else:
        llm_queries, reports = await analyze_project(aproject, model=model)

    logger.info(f"dumping llm queries for task: {str(task.task_id)}")
    model_name = model.split("/")[-1]
    path = config.LOGS_DIR / f"{task.task_id}-ainalysis-queries-{'multi' if multi else 'single'}-{model_name}.json"
    _ = await path.write_bytes(await asyncio.to_thread(orjson.dumps, llm_queries))

    return Ok([
        to_vuln_report(task, report, vuln) for report in reports for vuln in report.vulns
    ])
