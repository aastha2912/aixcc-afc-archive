#!/usr/bin/env python3
"""
Resolve actual fuzzer source paths from ARVO images.

This script:
1. Reads rows from eval_is.csv where the third column currently contains the
   /out harness binary path.
2. Runs the corresponding ARVO image (default: vulpatch:<id>-vul).
3. Searches /src inside the container for the most likely matching harness
   source file.
4. Writes a new CSV with the resolved /src path in the third column.

Usage:
    python3 crs/arvo-patching-agent/resolve_fuzzer_src_paths.py
    python3 crs/arvo-patching-agent/resolve_fuzzer_src_paths.py \
        --input crs/arvo-patching-agent/eval_is.csv \
        --output crs/arvo-patching-agent/eval_src_paths.csv

Notes:
- Requires Docker access on the machine where this script runs.
- By default it does not overwrite eval_is.csv.
"""

from __future__ import annotations

import argparse
import csv
import os
import shlex
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent


SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=str(SCRIPT_DIR / "eval_is.csv"),
        help="CSV containing id, project_name, and /out harness path",
    )
    parser.add_argument(
        "--output",
        default=str(SCRIPT_DIR / "eval_src_paths.csv"),
        help="Output CSV with resolved /src paths",
    )
    parser.add_argument(
        "--only-id",
        action="append",
        default=[],
        help="Limit processing to one or more ARVO IDs",
    )
    return parser.parse_args()


def image_name_for(arvo_id: str) -> str:
    prefix = os.environ.get("ARVO_IMAGE_PREFIX", "vulpatch")
    suffix = os.environ.get("ARVO_IMAGE_TAG_SUFFIX", "-vul")
    return f"{prefix}:{arvo_id}{suffix}"


def candidate_score(path: str, binary_name: str) -> tuple[int, int, int, str]:
    name = Path(path).name.lower()
    stem = Path(path).stem.lower()
    binary = binary_name.lower()
    path_l = path.lower()

    score = 0

    if stem == binary:
        score += 100
    if name == f"{binary}.c":
        score += 90
    if name == f"{binary}.cc":
        score += 90
    if name == f"{binary}.cpp":
        score += 90
    if name == f"{binary}.cxx":
        score += 90

    if binary in stem:
        score += 40
    if binary.replace("-", "") and binary.replace("-", "") in stem.replace("-", "").replace("_", ""):
        score += 20

    if "fuzz" in path_l or "fuzzer" in path_l or "fuzzing" in path_l:
        score += 20
    if "/test/" in path_l or "/tests/" in path_l:
        score += 8

    # Penalize obvious non-source matches.
    if path_l.endswith(".py"):
        score -= 50
    if "/fonts/" in path_l or "/corpus/" in path_l or "/seed/" in path_l:
        score -= 60

    # Prefer implementation files over headers when both exist.
    suffix = Path(path).suffix.lower()
    impl_bonus = 1 if suffix in {".c", ".cc", ".cpp", ".cxx"} else 0

    # Prefer shorter paths if scores tie.
    return (score, impl_bonus, -len(path), path)


def resolve_from_container(arvo_id: str, out_path: str) -> tuple[str, str]:
    if not out_path.strip():
        return "", "missing_out_path"

    binary_name = Path(out_path).name
    image = image_name_for(arvo_id)

    cmd = f"""
binary={shlex.quote(binary_name)}
find /src -type f 2>/dev/null | while read -r f; do
  base=$(basename "$f")
  case "$base" in
    "$binary"|"$binary".c|"$binary".cc|"$binary".cpp|"$binary".cxx|*"$binary"*)
      printf '%s\\n' "$f"
      ;;
    *)
      ;;
  esac
done
"""

    proc = subprocess.run(
        ["docker", "run", "--rm", image, "sh", "-lc", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode != 0:
        return "", f"docker_failed: {proc.stderr.strip()[:200]}"

    candidates = []
    for line in proc.stdout.splitlines():
        path = line.strip()
        if not path.startswith("/src/"):
            continue
        if Path(path).suffix.lower() not in SOURCE_SUFFIXES:
            continue
        candidates.append(path)

    if not candidates:
        fallback_cmd = f"grep -R -l {shlex.quote('LLVMFuzzerTestOneInput')} /src 2>/dev/null"
        fallback = subprocess.run(
            ["docker", "run", "--rm", image, "sh", "-lc", fallback_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if fallback.returncode == 0:
            for line in fallback.stdout.splitlines():
                path = line.strip()
                if not path.startswith("/src/"):
                    continue
                if Path(path).suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                if binary_name.lower() in path.lower():
                    candidates.append(path)

    if not candidates:
        return "", "no_match"

    best = sorted({c for c in candidates}, key=lambda p: candidate_score(p, binary_name), reverse=True)[0]
    return best, "ok"


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    rows = list(csv.DictReader(input_path.open()))
    only_ids = set(args.only_id)

    results = []
    for row in rows:
        arvo_id = row["id"]
        if only_ids and arvo_id not in only_ids:
            results.append(
                {
                    "id": row["id"],
                    "project_name": row["project_name"],
                    "Src Path": row["Src Path"],
                    "status": "skipped",
                }
            )
            continue

        resolved, status = resolve_from_container(arvo_id, row["Src Path"])
        results.append(
            {
                "id": row["id"],
                "project_name": row["project_name"],
                "Src Path": resolved,
                "status": status,
            }
        )
        print(f"{arvo_id}: {status} -> {resolved or '-'}", file=sys.stderr)

    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "project_name", "Src Path", "status"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Wrote {len(results)} rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
