#!/usr/bin/env python3
"""
SEC-Bench to CRS integration script (patch-focused)

Goal:
- Reuse Team Theori CRS agents (context retrieval intact) to patch SEC-Bench
  vulnerabilities without needing fuzz harnesses or sanitizer builds.
- Prefer a fast patch-only path using dataset metadata; fall back to CRS triage
  when metadata is thin.

What it does:
- Loads SEC-Bench config from secbench_<id>/config.json
- Ensures the project repo is available and checked out at base_commit
- Writes the provided build/repro scripts to disk (optional)
- Caches src.tar + workdir marker so CRS skips Dockerfile builds
- Seeds a synthetic harness so patcher can run without harness discovery
- Synthesizes CrashResult/POVRunData/DecodedPOV from sanitizer output or repro logs
- Runs CRS triage (optional safety net) then CRSPatcher with context capture
- Saves workflow artifacts (workflow_data.json, context_retrieval_data.json, generated_patch.diff)
"""
import asyncio
import hashlib
import json
import tarfile
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

# Make repo imports available
sys.path.insert(0, str(Path.cwd()))

from crs.common.types import CrashResult, POVRunData, DecodedPOV, AnalyzedVuln
from crs.modules.project import Harness, HarnessType
from crs.modules.testing import TestProject
from crs.app.app import CRS
from crs.agents.triage import CRSTriage
from crs.agents.produce_patch import CRSPatcher

# =============================================================================
# Configuration helpers
# =============================================================================

SEC_BENCH_CONFIG_DIR_NAME = "secbench_{secbench_id}"
SEC_BENCH_CONFIG_FILE_NAME = "config.json"


def load_secbench_config(secbench_id: str) -> dict:
    script_dir = Path(__file__).parent
    secbench_dir = script_dir / SEC_BENCH_CONFIG_DIR_NAME.format(secbench_id=secbench_id)
    config_file = secbench_dir / SEC_BENCH_CONFIG_FILE_NAME

    if not config_file.exists():
        print(f"Config not found: {config_file}")
        sys.exit(1)

    with open(config_file, "r") as f:
        return json.load(f)


def get_config_from_args() -> dict:
    if len(sys.argv) < 2:
        print("Usage: python3 secbench_to_crs_integration.py <SECBENCH_ID>")
        sys.exit(1)
    secbench_id = sys.argv[1]
    config = load_secbench_config(secbench_id)
    config["secbench_id"] = secbench_id
    print(f"Loaded SEC-Bench config for: {secbench_id}")
    return config


CONFIG = get_config_from_args()

REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = REPO_ROOT / "projects"

# Derived paths
PROJECT_NAME = CONFIG.get("project_name") or CONFIG.get("repo", "").split("/")[-1]
PROJECT_DIR = Path(CONFIG.get("project_dir", PROJECTS_DIR / PROJECT_NAME))
WORK_DIR = Path(CONFIG.get("work_dir", "."))
SEC_BENCH_DIR = Path(__file__).parent / SEC_BENCH_CONFIG_DIR_NAME.format(secbench_id=CONFIG["secbench_id"])

# =============================================================================
# Utilities
# =============================================================================

def run_cmd(cmd: list[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and capture output."""
    print(f"Running command: {' '.join(cmd)} (cwd={cwd or Path.cwd()})")
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stdout.decode(errors="replace"))
    return proc


def ensure_repo_checkout() -> None:
    """
    Ensure the repo exists at PROJECT_DIR and checkout base_commit.
    If the repo is missing and repo URL is provided, clone it.
    """
    repo_url = CONFIG.get("repo")
    base_commit = CONFIG.get("base_commit")

    if not PROJECT_DIR.exists():
        if not repo_url:
            raise RuntimeError(f"Project dir {PROJECT_DIR} missing and no repo URL provided")
        PROJECT_DIR.parent.mkdir(parents=True, exist_ok=True)
        run_cmd(["git", "clone", repo_url, str(PROJECT_DIR)], cwd=PROJECT_DIR.parent)

    if base_commit:
        run_cmd(["git", "fetch", "--all"], cwd=PROJECT_DIR, check=False)
        run_cmd(["git", "checkout", base_commit], cwd=PROJECT_DIR)


def write_script(path: Path, contents: str) -> Path:
    path.write_text(contents)
    path.chmod(0o755)
    print(f"Wrote script: {path}")
    return path


def materialize_scripts() -> Tuple[Optional[Path], Optional[Path]]:
    build_script = CONFIG.get("build_sh")
    secb_script = CONFIG.get("secb_sh")

    build_path = None
    secb_path = None

    if build_script:
        build_path = SEC_BENCH_DIR / "build.sh"
        write_script(build_path, build_script)
    if secb_script:
        secb_path = SEC_BENCH_DIR / "secb.sh"
        write_script(secb_path, secb_script)

    return build_path, secb_path


def compute_ossfuzz_hash() -> str:
    """
    Reuse the same hashing scheme CRS uses to locate cache directories.
    """
    projects_dir = PROJECT_DIR.parent
    proc_hash = run_cmd(
        ["git", "-C", str(projects_dir.absolute()), "log", "-1", "--pretty=format:'%H'", str(projects_dir.absolute())],
        check=False,
    )
    git_hash = proc_hash.stdout
    proc_diff = run_cmd(
        ["git", "-C", str(projects_dir.absolute()), "diff", str(projects_dir.absolute())],
        check=False,
    )
    git_diff = proc_diff.stdout

    h = hashlib.sha256()
    h.update(git_hash)
    h.update(git_diff)
    return h.hexdigest()


def cache_src_tar(ossfuzz_hash: str, workdir: str) -> Path:
    """
    Create src.tar and workdir marker so CRS skips Dockerfile builds.
    """
    from crs import config

    data_dir = Path(config.CACHE_DIR) / "data" / ossfuzz_hash / PROJECT_DIR.name
    data_dir.mkdir(parents=True, exist_ok=True)
    tar_path = data_dir / "src.tar"
    workdir_marker = data_dir / "arvo_workdir.txt"  # reuse ARVO marker to skip build

    if not tar_path.exists():
        print(f"Creating cached src.tar at {tar_path}")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(PROJECT_DIR, arcname=".")
    else:
        print(f"Using existing src.tar at {tar_path}")

    workdir_marker.write_text(workdir)
    print(f"Wrote workdir marker: {workdir}")
    return tar_path


def ensure_project_yaml() -> Path:
    """
    Create a minimal project.yaml if missing.
    """
    project_yaml = PROJECT_DIR / "project.yaml"
    if project_yaml.exists():
        return project_yaml

    language = CONFIG.get("lang", "c++")
    main_repo = CONFIG.get("repo", f"https://example.com/{PROJECT_NAME}")
    sanitizers = CONFIG.get("sanitizer", "address")

    yaml_contents = (
        f"homepage: \"https://example.com/{PROJECT_NAME}\"\n"
        f"language: {language}\n"
        f"primary_contact: \"\"\n"
        f"sanitizers:\n"
        f"  - {sanitizers}\n"
        f"main_repo: '{main_repo}'\n"
        f"fuzzing_engines:\n"
        f"  - libfuzzer\n"
    )
    project_yaml.write_text(yaml_contents)
    print(f"Created minimal project.yaml at {project_yaml}")
    return project_yaml


def parse_stack_from_output(output: str, repo_root: Path) -> Tuple[str, str]:
    """
    Extract a simple stack + dedup from sanitizer output. If no stack frames found,
    use the whole output.
    """
    lines = output.splitlines()
    stack_lines = []
    for line in lines:
        if " in " in line and ":" in line:
            cleaned = line.replace(str(repo_root), "")
            stack_lines.append(cleaned.strip())
    if not stack_lines:
        stack_lines = [l.strip() for l in lines if l.strip()]
    stack_text = "\n".join(stack_lines)
    dedup = hashlib.sha256(stack_text.encode()).hexdigest()
    return stack_text, dedup


async def synthesize_crash_and_pov(task, crash_output: str) -> Tuple[CrashResult, POVRunData, DecodedPOV]:
    """
    Build CrashResult + POVRunData + DecodedPOV using repro output.
    """
    stack, dedup = parse_stack_from_output(crash_output, PROJECT_DIR)
    build_config = task.project.info.default_build_config

    crash_result = CrashResult(
        config=build_config,
        input=b"",
        output=crash_output,
        dedup=dedup,
        stack=stack,
    )

    pov_run_data = POVRunData(
        task_uuid=task.task_id,
        project_name=task.project.name,
        harness="secbench-harness",
        sanitizer=build_config.SANITIZER,
        engine=build_config.FUZZING_ENGINE,
        python="",
        input=b"",
        output=crash_output,
        dedup=dedup,
        stack=stack,
    )
    decoded_pov = DecodedPOV.create(pov_run_data, decoding="<decoding>synthetic pov from secbench repro</decoding>")
    return crash_result, pov_run_data, decoded_pov


def build_analyzed_vuln(stack: str) -> AnalyzedVuln:
    """
    Build AnalyzedVuln from config hints.
    """
    file_hint = CONFIG.get("vuln_file") or CONFIG.get("bug_file") or "unknown.c"
    func_hint = CONFIG.get("function") or CONFIG.get("bug_function") or "unknown_function"
    description = CONFIG.get("description") or CONFIG.get("bug_description") or "SEC-Bench vulnerability"
    cwe = CONFIG.get("cwe", "")
    if cwe:
        description = f"{description} (CWE: {cwe})"
    conditions = CONFIG.get("conditions") or "Triggered via provided secbench repro/test command."
    return AnalyzedVuln(
        function=func_hint,
        file=file_hint,
        description=description,
        conditions=conditions + f"\nStack hint:\n{stack[:400]}",
    )


def seed_synthetic_harness(task) -> None:
    """
    Seed a synthetic harness to bypass harness discovery.
    """
    source = CONFIG.get("vuln_file") or "unknown.c"
    harness = Harness(
        name="secbench-harness",
        type=HarnessType.LIBFUZZER,
        source=source,
        options="",
        harness_func=None,
    )
    task.project.harnesses = [harness]
    print(f"Seeded synthetic harness for {source}")


def save_workflow_data(workflow_data: dict, secbench_id: str) -> Path:
    workflow_file = SEC_BENCH_DIR / "workflow_data.json"
    workflow_file.write_text(json.dumps(workflow_data, indent=2))
    print(f"Saved workflow data to: {workflow_file}")
    return workflow_file


def save_context_capture(context_capture: dict, secbench_id: str) -> Path:
    context_file = SEC_BENCH_DIR / "context_retrieval_data.json"
    context_file.write_text(json.dumps(context_capture, indent=2))
    print(f"Saved context retrieval data to: {context_file}")
    return context_file


def save_patch(patch_text: str, secbench_id: str) -> Path:
    patch_file = SEC_BENCH_DIR / "generated_patch.diff"
    patch_file.write_text(patch_text)
    print(f"Saved patch to: {patch_file}")
    return patch_file


# =============================================================================
# Main workflow
# =============================================================================

async def run_secbench_workflow(secbench_id: str):
    print("\n" + "=" * 60)
    print(f"SEC-Bench Integration (patch-first) - ID: {secbench_id}")
    print("=" * 60)
    ensure_repo_checkout()
    ensure_project_yaml()
    build_script_path, secb_script_path = materialize_scripts()

    # Optional build step
    if build_script_path:
        print("Running build script...")
        run_cmd(["bash", str(build_script_path)], cwd=PROJECT_DIR)

    # Optional repro command
    repro_cmd = CONFIG.get("repro_cmd")
    crash_output = ""
    if repro_cmd:
        proc = run_cmd(["bash", "-c", repro_cmd], cwd=PROJECT_DIR / WORK_DIR, check=False)
        crash_output = proc.stdout.decode(errors="replace")
    elif secb_script_path:
        proc = run_cmd(["bash", str(secb_script_path), "repro"], cwd=PROJECT_DIR, check=False)
        crash_output = proc.stdout.decode(errors="replace")
    else:
        print("No repro command provided; continuing with synthetic crash output.")
        crash_output = CONFIG.get("sanitizer_report", CONFIG.get("bug_report", ""))

    # Cache src.tar + workdir to skip Dockerfile build
    ossfuzz_hash = compute_ossfuzz_hash()
    workdir = str(Path("/src") / PROJECT_DIR.name / WORK_DIR)
    cache_src_tar(ossfuzz_hash, workdir)

    # Load project/task via CRS
    project = await TestProject.from_dir(PROJECT_DIR)
    task = await project.task()

    # Override build image if provided
    if CONFIG.get("build_image"):
        task.project.build_image = CONFIG["build_image"]

    # Seed harness to bypass harness discovery
    seed_synthetic_harness(task)

    # Build CrashResult / POV
    crash_result, pov_run_data, decoded_pov = await synthesize_crash_and_pov(task, crash_output)

    # Optionally triage if metadata is thin
    triage_needed = not CONFIG.get("vuln_file") or not CONFIG.get("function")
    triage_agent = None
    analyzed_vuln = build_analyzed_vuln(crash_result.stack)
    triage_llm_calls = []

    if triage_needed:
        print("Metadata thin -> running CRS triage agent for better targeting")
        crs_instance = CRS()
        triage_agent = CRSTriage.from_task(task)
        triage_result = await triage_agent.pov_triage(decoded_pov)
        if triage_result.is_ok():
            analyzed_vuln = triage_result.unwrap()
            triage_llm_calls = triage_agent.get_llm_calls()
            print(f"Triage updated vuln to {analyzed_vuln.file}:{analyzed_vuln.function}")
        else:
            print(f"Triage failed, using dataset hints: {triage_result.err()}")

    # Patch with CRS (context retrieval)
    patcher = CRSPatcher.from_task(task)
    patch_result = await patcher.patch_vulnerability(analyzed_vuln, [decoded_pov], rawdiff=False)

    context_capture = patcher.get_context_capture()
    patch_llm_calls = patcher.get_llm_calls()

    workflow_data = {
        "secbench_id": secbench_id,
        "project": task.project.name,
        "crash_result": {
            "output": crash_result.output[:500],
            "stack": crash_result.stack[:500],
            "dedup": crash_result.dedup,
        },
        "decoded_pov": {
            "harness": decoded_pov.harness,
            "dedup": decoded_pov.dedup,
            "decoding": decoded_pov.decoding[:500],
        },
        "analyzed_vuln": {
            "function": analyzed_vuln.function,
            "file": analyzed_vuln.file,
            "description": analyzed_vuln.description,
            "conditions": analyzed_vuln.conditions,
        },
        "cost_analysis": {
            "triage": triage_llm_calls,
            "patching": patch_llm_calls,
        },
    }

    if patch_result.is_ok() and patch_result.unwrap().success:
        patch_response = patch_result.unwrap()
        workflow_data["patch_result"] = {
            "success": True,
            "patch_chars": len(patch_response.patch),
            "build_artifacts": len(patch_response.build_artifacts or []),
        }
        save_patch(patch_response.patch, secbench_id)
    else:
        workflow_data["patch_result"] = {
            "success": False,
            "error": str(patch_result.err()) if patch_result.is_err() else "unknown failure",
        }

    save_workflow_data(workflow_data, secbench_id)
    save_context_capture(context_capture, secbench_id)

    print("\n" + "=" * 60)
    print("SEC-Bench workflow finished")
    print(f"Patch success: {workflow_data['patch_result']['success']}")
    print(f"Context calls: {sum(len(v) for v in context_capture.values())}")
    print(f"Artifacts saved under: {SEC_BENCH_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    secbench_id = CONFIG["secbench_id"]
    try:
        asyncio.run(run_secbench_workflow(secbench_id))
    except Exception as e:
        print(f"\n{'='*60}")
        print("FATAL ERROR during SEC-Bench workflow")
        print(f"{e}")
        import traceback
        traceback.print_exc()
        print(f"{'='*60}")
        sys.exit(1)
