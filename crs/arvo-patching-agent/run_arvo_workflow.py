#!/usr/bin/env python3
"""
Batch runner for the ARVO -> CRS workflow.

This script automates, for each requested ARVO ID:
1. `setup_arvo_project.py` if config is missing
2. copying the prebuilt image into the CRS DinD daemon if needed
3. running `arvo_to_crs_integration.py` inside `crs-main`

It skips IDs that already have `workflow_data.json` unless `--force` is used.
Parallel execution is only enabled when the selected IDs target distinct projects,
because CRS caches build state by project name rather than by ARVO ID.
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
SETUP_SCRIPT = SCRIPT_DIR / "setup_arvo_project.py"
INTEGRATION_SCRIPT_IN_CONTAINER = "/crs/crs/arvo-patching-agent/arvo_to_crs_integration.py"
DEFAULT_IDS_FILE = SCRIPT_DIR / "ids.csv"
MAX_PARALLEL_IDS = 10
STATUS_FILE = SCRIPT_DIR / "run_arvo_workflow_status.json"
STATUS_LOCK = Lock()


@dataclass(frozen=True)
class ArvoRunConfig:
    arvo_id: str
    project_name: str
    arvo_image_name: str


@dataclass(frozen=True)
class RunResult:
    arvo_id: str
    status: str
    detail: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the ARVO -> CRS workflow for one or more IDs."
    )
    parser.add_argument(
        "ids",
        nargs="*",
        help="ARVO IDs to run directly.",
    )
    parser.add_argument(
        "--id",
        dest="extra_ids",
        action="append",
        default=[],
        help="ARVO ID to run. Can be repeated.",
    )
    parser.add_argument(
        "--ids-file",
        default=str(DEFAULT_IDS_FILE),
        help=f"CSV/TXT file containing IDs (default: {DEFAULT_IDS_FILE}).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all IDs from --ids-file.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_PARALLEL_IDS,
        help=f"Requested concurrency. Actual concurrency is capped at {MAX_PARALLEL_IDS} and may drop to 1 when unsafe.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run IDs even when workflow_data.json already exists.",
    )
    return parser.parse_args()


def run_command(
    cmd: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
    stdout=None,
    stderr=None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )


def read_ids_from_file(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"IDs file not found: {path}")

    ids: list[str] = []
    if path.suffix.lower() == ".csv":
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                arvo_id = (row.get("id") or "").strip()
                if arvo_id:
                    ids.append(arvo_id)
    else:
        with path.open() as handle:
            for line in handle:
                arvo_id = line.strip()
                if arvo_id and arvo_id.lower() != "id":
                    ids.append(arvo_id)
    return ids


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def arvo_dir(arvo_id: str) -> Path:
    return SCRIPT_DIR / f"arvo_{arvo_id}"


def config_path(arvo_id: str) -> Path:
    return arvo_dir(arvo_id) / "config.json"


def workflow_path(arvo_id: str) -> Path:
    return arvo_dir(arvo_id) / "workflow_data.json"


def log_path(arvo_id: str) -> Path:
    return arvo_dir(arvo_id) / "batch_runner.log"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_log(arvo_id: str, message: str) -> None:
    path = log_path(arvo_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(f"[{now_iso()}] {message}\n")


def load_status_data() -> dict:
    if not STATUS_FILE.exists():
        return {"updated_at": now_iso(), "ids": {}}
    with STATUS_FILE.open() as handle:
        return json.load(handle)


def update_status(arvo_id: str, stage: str, status: str, detail: str = "") -> None:
    with STATUS_LOCK:
        data = load_status_data()
        ids = data.setdefault("ids", {})
        entry = ids.setdefault(arvo_id, {})
        entry.update(
            {
                "stage": stage,
                "status": status,
                "detail": detail,
                "updated_at": now_iso(),
                "log_file": str(log_path(arvo_id).relative_to(REPO_ROOT)),
            }
        )
        data["updated_at"] = now_iso()
        tmp_path = STATUS_FILE.with_suffix(".json.tmp")
        with tmp_path.open("w") as handle:
            json.dump(data, handle, indent=2)
        tmp_path.replace(STATUS_FILE)


def load_run_config(arvo_id: str) -> ArvoRunConfig | None:
    path = config_path(arvo_id)
    if not path.exists():
        return None
    with path.open() as handle:
        data = json.load(handle)
    return ArvoRunConfig(
        arvo_id=str(data["arvo_id"]),
        project_name=data["project_name"],
        arvo_image_name=data["arvo_image_name"],
    )


def ensure_setup(arvo_id: str) -> ArvoRunConfig:
    cfg = load_run_config(arvo_id)
    if cfg is not None:
        return cfg

    run_setup_script(arvo_id)
    cfg = load_run_config(arvo_id)
    if cfg is None:
        raise RuntimeError(f"setup completed but config.json is still missing for {arvo_id}")
    return cfg


def run_setup_script(arvo_id: str) -> None:
    append_log(arvo_id, "Running setup_arvo_project.py")
    update_status(arvo_id, stage="setup", status="running", detail="running setup_arvo_project.py")
    proc = run_command([sys.executable, str(SETUP_SCRIPT), arvo_id], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        append_log(arvo_id, f"setup_arvo_project.py failed\n{proc.stdout}")
        update_status(arvo_id, stage="setup", status="failed", detail="setup_arvo_project.py failed")
        raise RuntimeError(
            f"setup_arvo_project.py failed for {arvo_id}\n{proc.stdout}"
        )
    append_log(arvo_id, "setup_arvo_project.py completed successfully")
    update_status(arvo_id, stage="setup", status="completed", detail="setup_arvo_project.py completed")


def workflow_already_present(arvo_id: str) -> bool:
    return workflow_path(arvo_id).exists()


def docker_image_in_dind(image_name: str) -> bool:
    proc = run_command(
        ["docker", "compose", "exec", "-T", "docker-daemon", "docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def docker_image_on_host(image_name: str) -> bool:
    proc = run_command(
        ["docker", "image", "inspect", image_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def ensure_image_in_dind(image_name: str) -> None:
    if docker_image_in_dind(image_name):
        return
    if not docker_image_on_host(image_name):
        raise RuntimeError(f"host Docker daemon is missing image {image_name}")

    save_proc = subprocess.Popen(
        ["docker", "save", image_name],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    load_proc = subprocess.Popen(
        ["docker", "compose", "exec", "-T", "docker-daemon", "docker", "load"],
        cwd=REPO_ROOT,
        stdin=save_proc.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    assert save_proc.stdout is not None
    save_proc.stdout.close()
    load_stdout, load_stderr = load_proc.communicate()
    save_stderr = b""
    if save_proc.stderr is not None:
        save_stderr = save_proc.stderr.read()
    save_returncode = save_proc.wait()
    if save_returncode != 0 or load_proc.returncode != 0:
        raise RuntimeError(
            "failed to load image into DinD\n"
            f"docker save rc={save_returncode}: {save_stderr.decode(errors='replace')}\n"
            f"docker load rc={load_proc.returncode}: {(load_stdout + load_stderr).decode(errors='replace')}"
        )


def remove_image_from_dind(image_name: str) -> None:
    proc = run_command(
        ["docker", "compose", "exec", "-T", "docker-daemon", "docker", "image", "rm", "-f", image_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"failed to remove image from DinD: {image_name}\n{proc.stdout}"
        )


def remove_project_cache(project_name: str) -> None:
    shell_cmd = f"rm -rf /cache/data/*/{shlex.quote(project_name)}"
    proc = run_command(
        ["docker", "compose", "exec", "-T", "crs-main", "bash", "-lc", shell_cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"failed to remove project cache for {project_name}\n{proc.stdout}"
        )


def run_integration(arvo_id: str, log_file: Path) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    update_status(arvo_id, stage="integration", status="running", detail="running arvo_to_crs_integration.py inside crs-main")
    shell_cmd = (
        f"source /crs/.venv/bin/activate && "
        f"python3 {shlex.quote(INTEGRATION_SCRIPT_IN_CONTAINER)} {shlex.quote(arvo_id)}"
    )
    with log_file.open("a") as handle:
        handle.write(f"\n=== Running ARVO ID {arvo_id} ===\n")
        handle.flush()
        proc = run_command(
            ["docker", "compose", "exec", "-T", "crs-main", "bash", "-lc", shell_cmd],
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        if proc.returncode != 0:
            update_status(arvo_id, stage="integration", status="failed", detail=f"integration failed; see {log_file.name}")
            raise RuntimeError(
                f"arvo_to_crs_integration.py failed for {arvo_id}; see {log_file}"
            )
    update_status(arvo_id, stage="integration", status="completed", detail="integration completed successfully")


def process_id(arvo_id: str, *, force: bool) -> RunResult:
    if workflow_already_present(arvo_id) and not force:
        update_status(arvo_id, stage="skip", status="skipped", detail=f"{workflow_path(arvo_id).name} already exists")
        return RunResult(arvo_id=arvo_id, status="skipped", detail=f"{workflow_path(arvo_id).name} already exists")

    update_status(arvo_id, stage="starting", status="running", detail="starting workflow")
    cfg = ensure_setup(arvo_id)
    try:
        append_log(arvo_id, f"Ensuring image in DinD: {cfg.arvo_image_name}")
        update_status(arvo_id, stage="image", status="running", detail=f"ensuring {cfg.arvo_image_name} is present in DinD")
        ensure_image_in_dind(cfg.arvo_image_name)
        append_log(arvo_id, f"Image ready in DinD: {cfg.arvo_image_name}")
        update_status(arvo_id, stage="image", status="completed", detail=f"{cfg.arvo_image_name} present in DinD")
        run_setup_script(arvo_id)
        cfg = ensure_setup(arvo_id)
        run_integration(arvo_id, log_path(arvo_id))
        update_status(arvo_id, stage="done", status="completed", detail=cfg.project_name)
        return RunResult(arvo_id=arvo_id, status="completed", detail=cfg.project_name)
    finally:
        try:
            append_log(arvo_id, f"Removing image from DinD: {cfg.arvo_image_name}")
            remove_image_from_dind(cfg.arvo_image_name)
            append_log(arvo_id, f"Removed image from DinD: {cfg.arvo_image_name}")
        except Exception as exc:  # noqa: BLE001
            append_log(arvo_id, f"WARNING: failed to remove image from DinD: {exc}")
        try:
            append_log(arvo_id, f"Removing CRS cache for project: {cfg.project_name}")
            remove_project_cache(cfg.project_name)
            append_log(arvo_id, f"Removed CRS cache for project: {cfg.project_name}")
        except Exception as exc:  # noqa: BLE001
            append_log(arvo_id, f"WARNING: failed to remove CRS cache: {exc}")


def process_config_with_project_lock(
    cfg: ArvoRunConfig,
    *,
    force: bool,
    project_locks: dict[str, Lock],
) -> RunResult:
    with project_locks[cfg.project_name]:
        return process_id(cfg.arvo_id, force=force)


def determine_effective_workers(configs: list[ArvoRunConfig], requested_workers: int) -> tuple[int, str]:
    if not configs:
        return 1, "no runnable IDs"

    capped_workers = max(1, min(requested_workers, MAX_PARALLEL_IDS, len(configs)))
    project_counts = Counter(cfg.project_name for cfg in configs)
    colliding_projects = sorted(project for project, count in project_counts.items() if count > 1)

    if colliding_projects:
        projects = ", ".join(colliding_projects)
        return capped_workers, (
            f"running with {capped_workers} worker(s); serializing IDs that share a CRS project cache: "
            f"{projects}"
        )

    return capped_workers, f"running with {capped_workers} worker(s); each ID targets a distinct project"


def main() -> int:
    args = parse_args()

    direct_ids = list(args.ids) + list(args.extra_ids)
    if args.all:
        selected_ids = read_ids_from_file(Path(args.ids_file))
    elif direct_ids:
        selected_ids = direct_ids
    else:
        selected_ids = read_ids_from_file(Path(args.ids_file))

    ids = dedupe_preserve_order(selected_ids)
    if not ids:
        print("No ARVO IDs selected.", file=sys.stderr)
        return 2

    with STATUS_LOCK:
        tmp_path = STATUS_FILE.with_suffix(".json.tmp")
        with tmp_path.open("w") as handle:
            json.dump({"updated_at": now_iso(), "ids": {}}, handle, indent=2)
        tmp_path.replace(STATUS_FILE)

    runnable_ids = ids if args.force else [arvo_id for arvo_id in ids if not workflow_already_present(arvo_id)]
    skipped_ids = [arvo_id for arvo_id in ids if arvo_id not in runnable_ids]

    configs: list[ArvoRunConfig] = []
    setup_failures: list[RunResult] = []
    for arvo_id in runnable_ids:
        try:
            configs.append(ensure_setup(arvo_id))
        except Exception as exc:  # noqa: BLE001
            update_status(arvo_id, stage="setup", status="failed", detail=str(exc))
            setup_failures.append(RunResult(arvo_id=arvo_id, status="failed", detail=str(exc)))

    ready_ids = [cfg.arvo_id for cfg in configs]
    effective_workers, reason = determine_effective_workers(configs, args.workers)
    print(reason)

    results: list[RunResult] = [RunResult(arvo_id=arvo_id, status="skipped", detail=f"{workflow_path(arvo_id).name} already exists") for arvo_id in skipped_ids]
    for arvo_id in skipped_ids:
        update_status(arvo_id, stage="skip", status="skipped", detail=f"{workflow_path(arvo_id).name} already exists")
    results.extend(setup_failures)

    config_by_id = {cfg.arvo_id: cfg for cfg in configs}
    if effective_workers == 1:
        for arvo_id in ready_ids:
            try:
                cfg = config_by_id[arvo_id]
                try:
                    append_log(arvo_id, f"Ensuring image in DinD: {cfg.arvo_image_name}")
                    update_status(arvo_id, stage="image", status="running", detail=f"ensuring {cfg.arvo_image_name} is present in DinD")
                    ensure_image_in_dind(cfg.arvo_image_name)
                    append_log(arvo_id, f"Image ready in DinD: {cfg.arvo_image_name}")
                    update_status(arvo_id, stage="image", status="completed", detail=f"{cfg.arvo_image_name} present in DinD")
                    run_setup_script(arvo_id)
                    cfg = ensure_setup(arvo_id)
                    run_integration(arvo_id, log_path(arvo_id))
                    results.append(RunResult(arvo_id=arvo_id, status="completed", detail=cfg.project_name))
                finally:
                    try:
                        append_log(arvo_id, f"Removing image from DinD: {cfg.arvo_image_name}")
                        remove_image_from_dind(cfg.arvo_image_name)
                        append_log(arvo_id, f"Removed image from DinD: {cfg.arvo_image_name}")
                    except Exception as exc:  # noqa: BLE001
                        append_log(arvo_id, f"WARNING: failed to remove image from DinD: {exc}")
                    try:
                        append_log(arvo_id, f"Removing CRS cache for project: {cfg.project_name}")
                        remove_project_cache(cfg.project_name)
                        append_log(arvo_id, f"Removed CRS cache for project: {cfg.project_name}")
                    except Exception as exc:  # noqa: BLE001
                        append_log(arvo_id, f"WARNING: failed to remove CRS cache: {exc}")
            except Exception as exc:  # noqa: BLE001
                update_status(arvo_id, stage="failed", status="failed", detail=str(exc))
                append_log(arvo_id, f"Workflow failed: {exc}")
                results.append(RunResult(arvo_id=arvo_id, status="failed", detail=str(exc)))
    else:
        project_locks = {project_name: Lock() for project_name in {cfg.project_name for cfg in configs}}
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = {
                executor.submit(
                    process_config_with_project_lock,
                    config_by_id[arvo_id],
                    force=True,
                    project_locks=project_locks,
                ): arvo_id
                for arvo_id in ready_ids
            }
            for future in as_completed(futures):
                arvo_id = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    update_status(arvo_id, stage="failed", status="failed", detail=str(exc))
                    append_log(arvo_id, f"Workflow failed: {exc}")
                    results.append(RunResult(arvo_id=arvo_id, status="failed", detail=str(exc)))

    order = {arvo_id: index for index, arvo_id in enumerate(ids)}
    results.sort(key=lambda item: order.get(item.arvo_id, len(order)))

    completed = [result for result in results if result.status == "completed"]
    skipped = [result for result in results if result.status == "skipped"]
    failed = [result for result in results if result.status == "failed"]

    print("\nSummary:")
    for result in results:
        print(f"  {result.arvo_id}: {result.status} - {result.detail}")

    print(
        f"\nTotals: completed={len(completed)} skipped={len(skipped)} failed={len(failed)}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
