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


def extract_row(arvo_id: str, workflow_file: Path) -> dict[str, object]:
    data = json.loads(workflow_file.read_text())

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
        "triage_cost_usd": triage.get("total_cost", 0),
        "patching_cost_usd": patching.get("total_cost", 0),
        "total_llm_calls": total.get("total_llm_calls", triage.get("total_llm_calls", 0) + patching.get("total_llm_calls", 0)),
        "failure_phase": data.get("phase", ""),
        "failure_error": data.get("error", ""),
        "patch_failure_reason": patch_result.get("failure_reason", patch_result.get("error", "")),
        "last_validation_status": patch_result.get("last_validation", {}).get("status", ""),
        "last_validation_message": patch_result.get("last_validation", {}).get("message", ""),
        "workflow_file": workflow_file.relative_to(script_dir.parent.parent).as_posix(),
    }


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    arvo_ids = selected_ids(script_dir, sys.argv)

    rows: list[dict[str, object]] = []
    for arvo_id in arvo_ids:
        workflow_file = script_dir / f"arvo_{arvo_id}" / "workflow_data.json"
        if not workflow_file.exists():
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
                    "triage_cost_usd": 0,
                    "patching_cost_usd": 0,
                    "total_llm_calls": 0,
                    "failure_phase": "",
                    "failure_error": "workflow_data.json not found",
                    "patch_failure_reason": "",
                    "last_validation_status": "",
                    "last_validation_message": "",
                    "workflow_file": "",
                }
            )
            continue

        rows.append(extract_row(arvo_id, workflow_file))

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
        "triage_cost_usd",
        "patching_cost_usd",
        "total_llm_calls",
        "failure_phase",
        "failure_error",
        "patch_failure_reason",
        "last_validation_status",
        "last_validation_message",
        "workflow_file",
    ]

    with output_file.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {output_file}")
