#!/usr/bin/env python3
"""Read-only status scan across all IDs in ids.csv, based on workflow_data.json.

Run from crs/arvo-patching-agent/ on the server:
    python3 check_totals.py
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

    no_data: list[str] = []
    failed: list[str] = []
    patched: list[str] = []
    no_patch: list[str] = []

    for arvo_id in ids:
        arvo_dir = SCRIPT_DIR / f"arvo_{arvo_id}"
        wf_path = arvo_dir / "workflow_data.json"
        if not wf_path.exists():
            no_data.append(arvo_id)
            continue

        # generated_patch.diff is only ever written on the success path in
        # arvo_to_crs_integration.py, so its existence is reliable proof a patch was
        # validated at some point - even if a *later* --force re-run of the same ID
        # subsequently failed and overwrote workflow_data.json's patch_result with
        # that later failure. Trust the file over a possibly-stale JSON field.
        if (arvo_dir / "generated_patch.diff").exists():
            patched.append(arvo_id)
            continue

        try:
            data = json.loads(wf_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            failed.append(arvo_id)
            print(f"  WARNING: {arvo_id} workflow_data.json unreadable: {exc}")
            continue

        if data.get("status") == "failed":
            failed.append(arvo_id)
        elif data.get("patch_result", {}).get("success"):
            patched.append(arvo_id)
        else:
            no_patch.append(arvo_id)

    total = len(ids)
    print(f"Total IDs in {IDS_FILE.name}: {total}\n")
    print(f"  Patched (success=True):  {len(patched)}")
    print(f"  Completed, no patch:     {len(no_patch)}")
    print(f"  Failed (status=failed):  {len(failed)}")
    print(f"  No data (not run yet):   {len(no_data)}")
    print(f"  {'-'*35}")
    print(f"  Sum check:               {len(patched)+len(no_patch)+len(failed)+len(no_data)} (should equal total)")

    print(f"\nFailed IDs ({len(failed)}): {' '.join(failed)}")
    print(f"\nNo-data IDs ({len(no_data)}): {' '.join(no_data)}")


if __name__ == "__main__":
    main()
