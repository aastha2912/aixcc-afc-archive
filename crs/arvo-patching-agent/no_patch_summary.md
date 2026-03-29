# No-Patch Summary

This file is the main cross-case summary for the `71` ARVO patching-agent runs that do not have a local `generated_patch.diff`.

Use [no_patch_case_analysis.md](/Users/aastham/Workspace/aixcc-afc-archive/crs/arvo-patching-agent/no_patch_case_analysis.md) for the full per-case breakdown.

## Failure Breakdown

- `genuine_no_patch_agent_stopped`: 43
- `genuine_patch_failed_validation`: 17
- `genuine_patch_failed_build`: 5
- `genuine_invalid_patch_hunk`: 5
- `rerun_path_resolution_issue`: 1

The dominant failure mode is not a bad candidate patch. It is failure to ever produce a concrete patch attempt.

## GT Patch Shape

Across the fetched GT patches, the dominant shapes are:

- `multi_file`: 43
- `bounds_or_size_check`: 41
- `adds_guard_if`: 38
- `cross_file_change`: 37
- `single_file`: 28
- `null_check_or_null_assignment`: 20
- `early_return_validation`: 11
- `validation_logic`: 9
- `memory_or_api_semantics`: 8

Interpretation:

- Many GT fixes are defensive validation changes.
- A large fraction are broader than a one-line edit in a single file.
- This helps explain why many runs stall before patch generation.

## GT Shape by Failure Type

For `genuine_no_patch_agent_stopped`:

- `multi_file`: 27
- `adds_guard_if`: 27
- `bounds_or_size_check`: 27
- `cross_file_change`: 24

For `genuine_patch_failed_validation`:

- `single_file`: 9
- `bounds_or_size_check`: 9
- `multi_file`: 8
- `cross_file_change`: 8

Interpretation:

- Broader GT fixes are more associated with "stopped without trying."
- Narrower GT fixes are more associated with "tried, but the candidate was wrong."

## Sanitizer Report vs Exploration vs GT

The metadata usually provides crash-state functions, not precise source file paths, so direct file-level comparison from the sanitizer report is limited.

Reliable alignment signals:

- crash-state function matches analyzed vulnerable function: `47 / 71`
- explored files overlap GT files: `8 / 71`
- attempted patch files overlap GT files: `2 / 71`

Interpretation:

- The system often understands the crashing function.
- The bigger failure is converting that function-level signal into correct file-level localization and then into an edit.

## Main Takeaway

The no-patch cases are best explained as a localization-to-edit failure:

- the agent often gets function-level signal from the crash
- but frequently fails to converge on the correct GT file or patch region
- and this becomes worse when the real fix is broader, validation-heavy, or multi-file

So the highest-value improvement area is not only better patch synthesis. It is stronger handoff from crash triage and context retrieval into concrete edit generation.

## Slack-Ready Breakdown

- Main result:
  - `43/71` were `no_patch_attempt`
  - `22/71` were `patch_attempt_failed`
  - `5/71` were `patch_construction_failure`
  - `1/71` was `environment_or_path_failure`

- Within the `43` no-patch-attempt cases:
  - `31` were `localization_failure`
  - `10` were `analysis_to_edit_handoff_failure`
  - `2` were `insufficient_localization`

- What those mean:
  - `localization_failure`
    - the agent focused on the wrong file/region
    - or got confused by path mismatch, code drift, or line drift
  - `analysis_to_edit_handoff_failure`
    - the agent got close to the right file
    - but still never called `apply_patch`
  - `insufficient_localization`
    - the run never converged enough to identify a concrete edit target

- Within the `22` patch-attempt-failed cases:
  - `13` were `semantic_patch_failure`
    - the agent tried a patch, but it was not the right fix
  - `5` were `localization_plus_patch_failure`
    - a patch was attempted in the wrong file or region
  - `4` were `patch_shape_failure`
    - the candidate patch broke the build or used a bad edit shape

- Other categories:
  - `patch_construction_failure -> malformed_patch_hunk -> patch_context_or_hunk_syntax_invalid`: `5`
  - `environment_or_path_failure -> path_resolution_issue -> nonexistent_file_path_targeted`: `1`

## Workflow Terms

- `explore for too long`
  - the agent keeps reading or searching code but never transitions to `apply_patch`

- `fail to commit to an edit`
  - the agent seems to understand the bug at a high level, but does not make a concrete code change

- `stop without producing a patch`
  - the run ends with no validated patch, sometimes without any patch attempt at all

- `agent/workflow design issue`
  - not necessarily a bug, but a limitation of the current architecture: it allows the model to stay in analysis mode and finish without forcing a patch attempt
