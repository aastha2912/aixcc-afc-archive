# SEC-Bench to CRS Integration (patch-first)

Patch SEC-Bench instances with Team Theori's CRS agents while keeping context retrieval. This flow prefers patch-only (using dataset metadata) and falls back to triage when the metadata is thin.

## Quickstart
1. Create `crs/secbench-patching-agent/secbench_<ID>/config.json` with fields:
   - `project_name`, `repo` (URL), `base_commit`
   - `work_dir` (relative to repo root)
   - `lang`, `sanitizer`
   - `build_sh` (string) and/or `secb_sh` (string) from the dataset
   - `repro_cmd` (optional override, else `bash secb.sh repro`)
   - `vuln_file`, `function`, `description`/`bug_description`, `cwe`
   - `sanitizer_report` or `bug_report` (used for stack/dedup if repro is missing)
2. Ensure the repo is available under `projects/<project_name>` (script clones if missing and `repo` is set).
3. Run:
   ```bash
   python3 crs/secbench-patching-agent/secbench_to_crs_integration.py <ID>
   ```

## What the script does
- Writes build/repro scripts from config, runs them to confirm the bug.
- Caches `src.tar` + workdir marker so CRS skips Dockerfile builds.
- Seeds a synthetic harness (no fuzzers required).
- Synthesizes `CrashResult`/`DecodedPOV`; triage runs only when file/function hints are missing.
- Runs `CRSPatcher` (context retrieval on) and saves:
  - `secbench_<ID>/workflow_data.json`
  - `secbench_<ID>/context_retrieval_data.json`
  - `secbench_<ID>/generated_patch.diff` (when successful)

## Notes
- Path normalization strips the repo root from sanitizer output.
- You can override `build_image` in config if you want to run tests inside a specific image.
- If metadata is strong (file/function), triage is skipped to save tokens; otherwise triage refines the target before patching.
