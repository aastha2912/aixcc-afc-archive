import json
from io import StringIO
from typing import Any

from pydantic import BaseModel, ValidationError
from rich.console import Console

from crs.common.aio import Path
from crs.modules.project import Task
from crs.common.types import VulnReport
from crs.common.sarif_model import SARIFSchema

buffer = StringIO()
console = Console(file=buffer, force_terminal=False, width=240, no_color=True)


def prepend_project_name(obj: Any, project_name: Path) -> None:
    """
    Use "project_name/some_path/some_code.c" style paths to match our CRS filesystem
    """
    if isinstance(obj, BaseModel):
        for field_name, field_value in obj:
            if field_name == "uri" and isinstance(field_value, str):
                setattr(obj, field_name, str(project_name / field_value))
            else:
                prepend_project_name(field_value, project_name)
    elif isinstance(obj, list):
        for item in obj:  # type: ignore
            prepend_project_name(item, project_name)
    elif isinstance(obj, dict):
        for value in obj.values():  # type: ignore
            prepend_project_name(value, project_name)


def magic_print(x: Any) -> str:
    if isinstance(x, BaseModel):
        x = x.model_dump(exclude_unset=True)
    console.print(x)
    x_pretty = buffer.getvalue()
    _ = buffer.truncate(0)
    _ = buffer.seek(0)
    return x_pretty


async def sarif_to_vuln_report(task: Task, sarif_raw: dict[str, Any]) -> VulnReport:
    """
    convert a SARIF report into our standard VulnReport format
    NOTE: `sarif` must follow this schema:
    https://github.com/aixcc-finals/example-crs-architecture/blob/986c7c2671bb2eb05d7196623d1d559def2252b1/docs/api/sarif-schema.json

    FYI: in a "run", the only required field is "tool".
    """

    try:
        sarif = SARIFSchema(**sarif_raw)
        repo_path = (await task.project.repo_path()).unwrap()
        prepend_project_name(sarif, repo_path)
        
        # AIxCC-only: both runs[] and results[] will contain a single object
        assert isinstance(sarif.runs, list)
        run = sarif.runs[0]
        assert isinstance(run.results, list)
        result = run.results[0]
    except (ValidationError, AssertionError):
        # sarif is not in correct format, return dump anyway
        return VulnReport(
            task_uuid=task.task_id,
            project_name=task.project.name,
            function="unknown",
            file="unknown",
            description=json.dumps(sarif_raw)
        )

    function = ""
    file = ""
    description = ""

    try:
        # Get relevant rule for this result entry
        rule = None
        if result.ruleId:
            rule_id = result.ruleId
        else:
            assert result.rule
            rule_id = result.rule.root.id
        if run.tool.driver.rules:
            rule_candidate = [x for x in run.tool.driver.rules if x.id == rule_id]
            assert len(rule_candidate) > 0
            rule = rule_candidate[0]

        # Get file/function/location
        location_list: list[str] = []
        function_list: list[str] = []
        if result.locations:
            for location in result.locations:
                if location.physicalLocation:
                    location_list.append(magic_print(location.physicalLocation))
                if location.logicalLocations:
                    for logical_location in location.logicalLocations:
                        if logical_location.kind in ["function", "member", "module", "namespace", "declaration"]:
                            function_list.append(magic_print(logical_location))
                        else:
                            location_list.append(magic_print(logical_location))
        file = "".join(location_list)
        function = "".join(function_list)

        description = (
            f"## Report\n"
            f"{magic_print(result)}\n"
            f"## Rule used to generate this report\n"
            f"{magic_print(rule)}\n"
        )
    except Exception:
        pass

    # Default fallback to raw sarif dump
    if not function:
        function = "unknown"
    if not file:
        file = "unknown"
    if not description:
        description = magic_print(result) + "\n" + magic_print(run.tool.driver.rules)

    return VulnReport(
        task_uuid=task.task_id,
        project_name=task.project.name,
        function=function,
        file=file,
        description=description,
    )
