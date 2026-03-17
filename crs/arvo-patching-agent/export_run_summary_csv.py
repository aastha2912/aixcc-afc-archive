#!/usr/bin/env python3
"""
Export a final ARVO run summary CSV.

The output is intended to answer operational questions quickly:
- did the run complete?
- was a patch generated?
- what was the total cost?

Usage:
    python crs/arvo-patching-agent/export_run_summary_csv.py --all
    python crs/arvo-patching-agent/export_run_summary_csv.py 12419 14637 14916
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


def selected_ids(script_dir: Path, argv: list[str]) -> list[str]:
    if len(argv) > 1 and argv[1] == "--all":
        return sorted(
            path.name.removeprefix("arvo_")
            for path in script_dir.glob("arvo_*")
            if path.is_dir()
        )
    if len(argv) > 1:
        return argv[1:]
    print("Usage: python export_run_summary_csv.py --all", file=sys.stderr)
    print("   or: python export_run_summary_csv.py <arvo_id> [arvo_id ...]", file=sys.stderr)
    raise SystemExit(1)


def bool_label(value: bool) -> str:
    return "yes" if value else "no"


def classify_failure(
    workflow_data: dict[str, object],
    log_text: str,
    has_workflow: bool,
) -> tuple[str, str]:
    if not has_workflow:
        if "usable harness target" in log_text:
            return (
                "needs_fix_metadata_harness",
                "metadata missing harness target; config fallback or metadata fix needed",
            )
        if "context_length_exceeded" in log_text:
            return (
                "needs_fix_context_window",
                "triage request exceeded model context window",
            )
        if "Fuzzer harness" in log_text and "not found" in log_text:
            return (
                "needs_fix_missing_harness",
                "configured harness was not found during setup",
            )
        if "workflow_data.json not found" in log_text:
            return ("missing_workflow", "workflow data was not generated")
        return ("needs_review_preworkflow_failure", "workflow failed before workflow_data.json was written")

    patch_result = workflow_data.get("patch_result", {})
    context = workflow_data.get("context_retrieval", {})
    apply_calls = context.get("apply_patch", []) if isinstance(context, dict) else []
    test_calls = context.get("test_patch", []) if isinstance(context, dict) else []

    if patch_result.get("success") is True:
        return ("success", "patch generated and validated")

    validation = patch_result.get("last_validation", {})
    validation_status = validation.get("status", "")
    if validation_status == "pov_still_crashes":
        return ("genuine_patch_failed_validation", "patch was produced but PoV still crashes")
    if validation_status == "build_failed":
        return ("genuine_patch_failed_build", "patch was produced but validation build failed")

    apply_summary = ""
    if apply_calls:
        apply_summary = apply_calls[-1].get("result_summary", "")

    if "Cannot call require() unless annotated with @requireable" in log_text:
        return ("rerun_runner_regression", "runner regression in source editor path resolution")

    if apply_calls and "does not exist in directory tree" in apply_summary:
        return ("rerun_path_resolution_issue", "patch targeted the wrong file path")

    if apply_calls and "typographic error" in apply_summary:
        return ("genuine_invalid_patch_hunk", "agent produced malformed patch hunks")

    if apply_calls and not test_calls:
        return ("review_apply_patch_attempt_no_result", "patch was attempted but never reached validation")

    if not apply_calls:
        return ("genuine_no_patch_agent_stopped", "patching completed without any patch attempt")

    return ("review_other_failed_patching", "failed during patching for an unclassified reason")


def extract_row(arvo_id: str, workflow_file: Path, log_file: Path) -> dict[str, object]:
    data = json.loads(workflow_file.read_text())
    log_text = log_file.read_text(errors="replace") if log_file.exists() else ""

    failed = data.get("status") == "failed"
    completed = not failed and "patch_result" in data
    patch_generated = bool(data.get("patch_result", {}).get("success"))

    pov_run_data = data.get("pov_run_data", {})
    analyzed_vuln = data.get("analyzed_vuln", {})
    cost_analysis = data.get("cost_analysis", {})
    triage = cost_analysis.get("triage", {})
    patching = cost_analysis.get("patching", {})
    total = cost_analysis.get("total", {})
    patch_result = data.get("patch_result", {})
    failure_category, failure_reason_summary = classify_failure(data, log_text, True)

    total_cost = total.get("total_cost")
    if total_cost is None:
        total_cost = triage.get("total_cost", 0) + patching.get("total_cost", 0)

    return {
        "arvo_id": arvo_id,
        "project": pov_run_data.get("project_name") or data.get("config", {}).get("project_name", ""),
        "harness": pov_run_data.get("harness") or data.get("config", {}).get("fuzzer_name", ""),
        "completed": bool_label(completed),
        "patch_generated": bool_label(patch_generated),
        "run_status": "failed" if failed else "completed",
        "vuln_id": data.get("vuln_id", ""),
        "vuln_function": analyzed_vuln.get("function", ""),
        "vuln_file": analyzed_vuln.get("file", ""),
        "total_cost_usd": total_cost,
        "total_llm_calls": total.get("total_llm_calls", triage.get("total_llm_calls", 0) + patching.get("total_llm_calls", 0)),
        "failure_category": failure_category,
        "failure_reason_summary": failure_reason_summary,
        "failure_phase": data.get("phase", ""),
        "failure_error": data.get("error", ""),
        "patch_failure_reason": patch_result.get("failure_reason", patch_result.get("error", "")),
        "last_validation_status": patch_result.get("last_validation", {}).get("status", ""),
        "last_validation_message": patch_result.get("last_validation", {}).get("message", ""),
    }


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    arvo_ids = selected_ids(script_dir, sys.argv)

    rows: list[dict[str, object]] = []
    for arvo_id in arvo_ids:
        workflow_file = script_dir / f"arvo_{arvo_id}" / "workflow_data.json"
        log_file = script_dir / f"arvo_{arvo_id}" / "batch_runner.log"
        if not workflow_file.exists():
            log_text = log_file.read_text(errors="replace") if log_file.exists() else ""
            failure_category, failure_reason_summary = classify_failure({}, log_text, False)
            rows.append(
                {
                    "arvo_id": arvo_id,
                    "project": "",
                    "harness": "",
                    "completed": "no",
                    "patch_generated": "no",
                    "run_status": "missing_workflow",
                    "vuln_id": "",
                    "vuln_function": "",
                    "vuln_file": "",
                    "total_cost_usd": 0,
                    "total_llm_calls": 0,
                    "failure_category": failure_category,
                    "failure_reason_summary": failure_reason_summary,
                    "failure_phase": "",
                    "failure_error": "workflow_data.json not found",
                    "patch_failure_reason": "",
                    "last_validation_status": "",
                    "last_validation_message": "",
                }
            )
            continue

        rows.append(extract_row(arvo_id, workflow_file, log_file))

    output_file = script_dir / "run_summary.csv"
    fieldnames = [
        "arvo_id",
        "project",
        "harness",
        "completed",
        "patch_generated",
        "run_status",
        "vuln_id",
        "vuln_function",
        "vuln_file",
        "total_cost_usd",
        "total_llm_calls",
        "failure_category",
        "failure_reason_summary",
        "failure_phase",
        "failure_error",
        "patch_failure_reason",
        "last_validation_status",
        "last_validation_message",
    ]

    with output_file.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_file}")
