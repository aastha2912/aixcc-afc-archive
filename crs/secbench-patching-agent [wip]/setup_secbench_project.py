#!/usr/bin/env python3
"""
Prepare a SEC-Bench instance for CRS patching.

Given an instance_id, this script:
  - Fetches the record from SEC-Bench (local JSON/JSONL or HuggingFace datasets)
  - Extracts repo/commit/build/repro/scripts and stack hints
  - Creates secbench_<id>/config.json with everything secbench_to_crs_integration.py needs

Usage:
  python3 setup_secbench_project.py <INSTANCE_ID> [--dataset-path /path/to/local.jsonl]

Notes:
  - Prefers a local dataset file (json/jsonl). Falls back to `datasets.load_dataset("SEC-bench/SEC-bench")` if available.
  - Does not clone the repo; secbench_to_crs_integration.py will clone if needed.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional, Tuple

SCRIPT_DIR = Path(__file__).parent
SEC_BENCH_DIR_TEMPLATE = "secbench_{secbench_id}"
CONFIG_FILE_NAME = "config.json"

# Regex to pull stack frames: function + path
STACK_LINE_RE = re.compile(
    r"in\s+(?P<func>[^\s]+)\s+(?P<path>/[^\s:]+?)(?::\d+(?::\d+)?)?"
)


def load_local_dataset(dataset_path: Path, instance_id: str) -> Optional[dict]:
    """Load a record from a local JSON/JSONL dataset."""
    if not dataset_path.exists():
        return None

    records = []
    if dataset_path.suffix.lower() in {".jsonl", ".ndjson"}:
        with dataset_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    records.append(rec)
                except json.JSONDecodeError:
                    continue
    elif dataset_path.suffix.lower() == ".json":
        data = json.loads(dataset_path.read_text())
        if isinstance(data, dict):
            # huggingface export format may have splits
            for split in ("train", "validation", "test"):
                if split in data and isinstance(data[split], list):
                    records.extend(data[split])
            if not records and "data" in data and isinstance(data["data"], list):
                records.extend(data["data"])
        elif isinstance(data, list):
            records = data
    else:
        return None

    for rec in records:
        if str(rec.get("instance_id")) == str(instance_id):
            return rec
    return None


def load_hf_dataset(instance_id: str) -> Optional[dict]:
    """Try loading from the HuggingFace datasets library (requires network or cached dataset)."""
    try:
        from datasets import load_dataset  # type: ignore
    except Exception:
        return None

    for split in ("train", "validation", "test"):
        try:
            ds = load_dataset("SEC-bench/SEC-bench", split=split)
        except Exception:
            continue
        for rec in ds:
            if str(rec.get("instance_id")) == str(instance_id):
                return dict(rec)
    return None


def extract_stack_hints(report_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract (file, function) hints from a sanitizer/bug report.
    Returns (vuln_file, function_name) if found.
    """
    vuln_file = None
    func = None
    for line in report_text.splitlines():
        m = STACK_LINE_RE.search(line)
        if m:
            func = func or m.group("func")
            raw_path = m.group("path")
            # Prefer segment after /src/
            if "/src/" in raw_path:
                vuln_file = raw_path.split("/src/", 1)[1]
            else:
                # Fallback: strip leading dirs
                vuln_file = "/".join(raw_path.split("/")[-3:])
            break
    return vuln_file, func


def build_config(instance_id: str, record: dict) -> dict:
    sanitizer_report = record.get("sanitizer_report") or record.get("bug_report") or ""
    vuln_file_hint, func_hint = extract_stack_hints(sanitizer_report)

    desc = (
        record.get("bug_description")
        or record.get("description")
        or "SEC-Bench vulnerability"
    )

    config = {
        "secbench_id": instance_id,
        "project_name": record.get("project_name") or record.get("repo", "").split("/")[-1],
        "project_dir": f"projects/{record.get('project_name') or record.get('repo', '').split('/')[-1]}",
        "repo": record.get("repo"),
        "base_commit": record.get("base_commit"),
        "work_dir": record.get("work_dir", "."),
        "lang": record.get("lang", "c++"),
        "sanitizer": record.get("sanitizer", "address"),
        "build_sh": record.get("build_sh", ""),
        "secb_sh": record.get("secb_sh", ""),
        "dockerfile": record.get("dockerfile", ""),
        "patch": record.get("patch", ""),
        "exit_code": record.get("exit_code"),
        "sanitizer_report": sanitizer_report,
        "bug_report": record.get("bug_report", ""),
        "description": desc,
        "vuln_file": record.get("vuln_file") or vuln_file_hint,
        "function": record.get("function") or func_hint,
        "cwe": record.get("cwe"),
    }

    # Optional manual override for repro
    if record.get("repro_cmd"):
        config["repro_cmd"] = record["repro_cmd"]

    return config


def write_config(secbench_dir: Path, config: dict) -> Path:
    secbench_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = secbench_dir / CONFIG_FILE_NAME
    cfg_path.write_text(json.dumps(config, indent=2))
    print(f"Wrote config: {cfg_path}")
    return cfg_path


def main():
    parser = argparse.ArgumentParser(description="Set up SEC-Bench instance config for CRS patching.")
    parser.add_argument("instance_id", help="SEC-Bench instance_id (e.g., njs.cve-2022-32414)")
    parser.add_argument("--dataset-path", help="Path to local SEC-Bench dataset (json/jsonl). If omitted, tries HuggingFace datasets.")
    args = parser.parse_args()

    instance_id = args.instance_id

    # Load record
    record = None
    if args.dataset_path:
        record = load_local_dataset(Path(args.dataset_path), instance_id)
    if record is None:
        record = load_hf_dataset(instance_id)
    if record is None:
        print("Could not find instance in dataset. Provide --dataset-path to a local SEC-Bench export.")
        sys.exit(1)

    config = build_config(instance_id, record)
    secbench_dir = SCRIPT_DIR / SEC_BENCH_DIR_TEMPLATE.format(secbench_id=instance_id)
    write_config(secbench_dir, config)

    # Save raw reports for inspection
    if record.get("sanitizer_report"):
        (secbench_dir / "sanitizer_report.txt").write_text(record["sanitizer_report"])
    if record.get("bug_report"):
        (secbench_dir / "bug_report.txt").write_text(record["bug_report"])

    print("\nDone. Next:")
    print(f"  python3 crs/secbench-patching-agent/secbench_to_crs_integration.py {instance_id}")


if __name__ == "__main__":
    main()
