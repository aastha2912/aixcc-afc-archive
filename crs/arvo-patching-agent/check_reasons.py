#!/usr/bin/env python3
"""Print failure/no-patch reasons for IDs in ids.csv, based on workflow_data.json.

Run from crs/arvo-patching-agent/ on the server:
    python3 check_reasons.py
"""
import csv
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
IDS_FILE = SCRIPT_DIR / "ids.csv"


def read_ids(path: Path) -> list[str]:
    ids = []
    if path.suffix.lower() == ".csv":
        with path.open(newline="") as f:
            for row in csv.DictReader(f):
                arvo_id = (row.get("id") or "").strip()
                if arvo_id:
                    ids.append(arvo_id)
    else:
        with path.open() as f:
            for line in f:
                arvo_id = line.strip()
                if arvo_id and arvo_id.lower() != "id":
                    ids.append(arvo_id)
    return ids


def main():
    ids = read_ids(IDS_FILE)

    failed_reasons: list[tuple[str, str]] = []
    no_patch_reasons: list[tuple[str, str]] = []

    for arvo_id in ids:
        wf_path = SCRIPT_DIR / f"arvo_{arvo_id}" / "workflow_data.json"
        if not wf_path.exists():
            continue
        try:
            data = json.loads(wf_path.read_text())
        except (json.JSONDecodeError, OSError):
            failed_reasons.append((arvo_id, "workflow_data.json unreadable"))
            continue

        if data.get("status") == "failed":
            phase = data.get("phase", "?")
            error = data.get("error", "?")
            failed_reasons.append((arvo_id, f"[{phase}] {error}"))
            continue

        patch_result = data.get("patch_result")
        if patch_result and not patch_result.get("success"):
            reason = patch_result.get("failure_reason") or patch_result.get("error") or "unknown"
            lv = patch_result.get("last_validation")
            if lv:
                reason += f" | last_validation: {lv.get('status')} - {lv.get('message')}"
            no_patch_reasons.append((arvo_id, reason))

    print(f"=== Failed ({len(failed_reasons)}) ===")
    for arvo_id, reason in failed_reasons:
        print(f"\n{arvo_id}:")
        print(f"  {reason}")

    print(f"\n\n=== Completed, no patch ({len(no_patch_reasons)}) ===")
    for arvo_id, reason in no_patch_reasons:
        print(f"\n{arvo_id}:")
        print(f"  {reason}")


if __name__ == "__main__":
    main()
