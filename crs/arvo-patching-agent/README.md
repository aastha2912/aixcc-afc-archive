# ARVO-to-CRS Integration Workflow

This directory contains scripts to automatically set up and run vulnerability analysis and patching workflows using ARVO (Automated Vulnerability Research and Operations) data with the CRS (Code Repair System).

## Overview

The system uses **prebuilt vulnerable Docker images** (by default: `vulpatch:{id}-vul`) which contain vulnerable versions of projects with pre-compiled binaries. This eliminates the need to build projects from source, significantly speeding up the workflow.

The scripts fetch vulnerability metadata from ARVO, download testcase files, pull prebuilt Docker images, and run the complete CRS workflow for vulnerability analysis and patch generation.

## Directory Structure

```
crs/arvo-patching-agent/
├── README.md                           # This file
├── setup_arvo_project.py              # Setup script (downloads metadata, testcase, project.yaml)
├── arvo_to_crs_integration.py         # Main workflow script (uses ARVO prebuilt images)
├── arvo_65027/                        # ARVO-specific directory (created automatically)
│   ├── config.json                    # Configuration for this ARVO ID
│   ├── testcase_5110826180411392.bin  # Downloaded POC file
│   ├── workflow_data.json             # Complete workflow execution data
│   ├── context_retrieval_data.json    # Context retrieval calls made by patching agent
│   └── generated_patch.diff           # Generated patch (if successful)
├── arvo_12345/                        # Another ARVO ID directory
│   └── ...
└── ../../projects/                    # Project directories (minimal, in parent folder)
    └── libraw/
        └── project.yaml               # OSS-Fuzz project configuration (downloaded)
```

**Note:** No Dockerfile or build scripts needed - everything comes from ARVO prebuilt images!

## Quick Start

### 1. Setup ARVO Project

```bash
# From the main project directory
python3 crs/arvo-patching-agent/setup_arvo_project.py <ARVO_ID>
```

**Example:**
```bash
python3 crs/arvo-patching-agent/setup_arvo_project.py 65027
```

This will:
- Fetch ARVO metadata for the specified ID
- Download the testcase file to `arvo_<ID>/` directory
- Download project.yaml from OSS-Fuzz
- Create ARVO-specific directory with configuration
- Save all configuration to `arvo_<ID>/config.json` including ARVO image name

### 2. Run CRS Integration

```bash
# From the main project directory
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py <ARVO_ID>"
```

**Example:**
```bash
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 65027"
```

This will:
- Load configuration from `arvo_<ID>/config.json`
- Pull prebuilt image (e.g. `vulpatch:{id}-vul`)
- Extract source code and binaries from image (no building!)
- Run the complete CRS workflow:
  1. Setup project and harnesses (using ARVO prebuilt)
  2. **Run `arvo run` to get authentic crash** (uses prebuilt vulnerable binary)
  3. Parse ARVO crash output (strips `/src/` prefix from paths)
  4. Create POVRunData from crash
  5. Decode POV
  6. Triage vulnerability with LLM
  7. Store vulnerability in database
  8. Run patching agent with context retrieval
  9. Generate patches
- Save all outputs to the ARVO-specific directory

**Fast:** No Dockerfile build, no compilation, no CRS rebuild - uses authentic ARVO crash data!

**Note:** This workflow is **prebuilt-image-only**. If the prebuilt image isn't available (inspect/pull/run fails),
the script will **fail fast** rather than falling back to building from source.

#### Loading images into DinD (required for this stack)

This compose stack uses a Docker-in-Docker daemon (`docker-daemon`) via `DOCKER_HOST=tcp://docker-daemon:2375`.
That daemon does **not** share images with the host Docker daemon, so if `vulpatch:<id>-vul` exists on the host, CRS
still won’t see it until it’s loaded into DinD.

Use the helper script (safe to rerun; skips images already present in DinD):

```bash
# If the script isn't executable, prefix with bash:
bash crs/arvo-patching-agent/load_images_into_dind.sh 10084
# or
bash crs/arvo-patching-agent/load_images_into_dind.sh --file crs/arvo-patching-agent/ids.csv
```

## Detailed Workflow

### Phase 1: Project Setup (`setup_arvo_project.py`)

1. **Fetch ARVO Metadata**
   - Downloads metadata from `https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/<ARVO_ID>.json`
   - Extracts project name, fuzzer name (from "Fuzz target binary"), testcase URL, etc.

2. **Download Testcase File**
   - Downloads the testcase from OSS-Fuzz to `arvo_<ID>/` directory
   - Saves with `testcase_` prefix (e.g., `testcase_5110826180411392.bin`)

3. **Download project.yaml**
   - Downloads from `https://raw.githubusercontent.com/google/oss-fuzz/master/projects/<project>/project.yaml`
   - This is the only OSS-Fuzz file needed (provides metadata like language, main_repo)

4. **Create Configuration**
   - Creates `arvo_<ID>/` directory
   - Saves configuration to `arvo_<ID>/config.json` including:
     - `arvo_image_name`: Docker image to pull (e.g., `vulpatch:65027-vul`)
     - `use_prebuilt_image`: true (default)

### Phase 2: CRS Integration (`arvo_to_crs_integration.py`)

1. **Pull Prebuilt Vulnerable Image**
   - Checks if `vulpatch:{id}-vul` exists locally
   - Pulls image if needed (contains vulnerable version + prebuilt binaries)

2. **Extract from ARVO Image**
   - Extracts `/src` → source code (skips Dockerfile build!)
   - Extracts `/out` → prebuilt vulnerable binaries (skips compilation!)
   - Gets workdir from image metadata
   - Sets `build_image` to ARVO image for all operations

3. **Setup Project and Harnesses**
   - Loads project using CRS TestProject
   - Uses cached source and binaries from ARVO
   - Initializes harness information
   - Finds the specified fuzzer harness

4. **Get Authentic Crash from ARVO** (when `use_prebuilt_image: true`)
   - Runs `arvo run {fuzzer} /testcase` using ARVO's prebuilt vulnerable binary
   - Captures raw crash output from ARVO (authentic crash, no rebuild issues)
   - Parses stack trace and deduplication token
   - Strips `/src/` prefix from file paths to match CRS VFS format
   - Creates `CrashResult` object for CRS workflow
   - **Fallback**: If ARVO run fails, falls back to CRS `test_pov()` with rebuilding

5. **Create POVRunData**
   - Creates POVRunData structure exactly like CRS does
   - Includes task UUID, project name, harness, sanitizer, engine, etc.

6. **Decode POV**
   - Uses CRS decode_pov function to decode the crash
   - Extracts vulnerability information

7. **Triage Vulnerability**
   - Runs CRS Triage Agent with LLM
   - Analyzes the vulnerability and identifies the vulnerable function/file
   - Uses AST-based navigation if bear build succeeds, text-based otherwise

8. **Store in Database**
   - Stores vulnerability in CRS products database
   - Returns vulnerability ID for tracking

9. **Run Patching Agent**
   - Creates CRS Patcher instance
   - Runs patching agent with context retrieval
   - Captures all context retrieval calls (source_questions, read_definition, find_references, etc.)
   - Generates patches for the vulnerable code

10. **Save Outputs**
    - Saves workflow data to `arvo_<ID>/workflow_data.json`
    - Saves context retrieval data to `arvo_<ID>/context_retrieval_data.json`
    - Saves generated patch to `arvo_<ID>/generated_patch.diff`

## Why Use ARVO Crash Data Directly?

The integration now uses `arvo run` to capture crash data instead of CRS `test_pov()`. This solves critical issues:

### Problem with CRS Rebuild:
- CRS `test_pov()` rebuilds binaries from `/src` source
- ARVO images may have `/src` and `/out` from **different commits/states**
- Rebuilding can trigger **different crashes** than the original ARVO report
- Example: libraw 65027 expected `libraw_tagtype_dataunit_bytes` crash, but CRS rebuild triggered `DHT::DHT` crash

### Solution with ARVO Run:
- ✅ Uses ARVO's prebuilt `/out` binaries (exact vulnerable version)
- ✅ Gets authentic crash matching ARVO's report
- ✅ No rebuild = no cache invalidation issues
- ✅ Faster (~5 min vs ~20 min for large projects)
- ✅ Correct patches for the actual vulnerability

### Path Normalization:
- ARVO stack traces show: `/src/ghostpdl/pdf/file.c`
- CRS VFS expects: `ghostpdl/pdf/file.c`
- Integration automatically strips `/src/` prefix from paths
- Ensures agent tools (`read_source`, `find_references`) work correctly

## Configuration

### Environment Variables

The system uses the existing CRS environment variables:
- `MODEL_MAP`: Path to model configuration file (e.g., `/crs/configs/models-best.toml`)
- Database connections and other CRS settings

#### Optional: LLM spend budget (USD)

You can cap total LLM spend for a single run (recommended: **one ARVO ID per process**) by setting:

- `CRS_LLM_BUDGET_USD`: maximum dollars to spend before CRS stops making additional LLM calls.

Example (set a very low budget to verify the cutoff behavior):

```bash
docker compose exec crs-main bash -lc 'export CRS_LLM_BUDGET_USD=0.01; source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 10084'
```

### Model Configuration

The system respects the model configuration in `configs/models-best.toml`. Make sure this file contains the models you want to use for:
- Triage agent (vulnerability analysis)
- Patching agent (patch generation)

## Output Files

### Configuration File (`arvo_<ID>/config.json`)
```json
{
  "arvo_id": "65027",
  "project_name": "libraw",
  "fuzzer_name": "libraw_fuzzer",
  "sanitizer": "asan",
  "crash_type": "Global-buffer-overflow READ 4",
  "fix_commit": "a6f212a4a1fe19dce1f83c83384f171fd7babb0a",
  "repo_addr": "https://github.com/libraw/libraw",
  "project_dir": "projects/libraw",
  "poc_file": "crs/arvo-patching-agent/arvo_65027/testcase_5110826180411392.bin",
  "arvo_image_name": "vulpatch:65027-vul",
  "use_prebuilt_image": true
}
```

### Workflow Data (`arvo_<ID>/workflow_data.json`)
Contains complete workflow execution data:
- Crash results (output, stack trace, dedup ID)
- POV run data (task UUID, project, harness, sanitizer)
- Decoded POV information
- Analyzed vulnerability (function, file, description, conditions)
- Patch results (success/failure, patch content, build artifacts)
- On failure, `workflow_data.json` is still written with `status: "failed"`, the failing phase, and the exception/traceback.

### Context Retrieval Data (`arvo_<ID>/context_retrieval_data.json`)
Detailed information about all context retrieval calls made by the patching agent:
- `source_questions`: Natural language questions asked about the code
- `read_definition`: Function definitions read
- `read_source`: Source code files read
- `find_references`: Function references found
- `apply_patch`: Patches applied
- `undo_last_patch`: Patches undone
- `list_current_edits`: Current edits listed

### Generated Patch (`arvo_<ID>/generated_patch.diff`)
The actual patch generated by the CRS patching agent (if successful).

## Troubleshooting

### Common Issues

1. **Configuration file not found**
   ```
   Configuration file not found: /path/to/arvo_65027/config.json
   Please run setup_arvo_project.py first to create the configuration.
   ```
   **Solution**: Run `setup_arvo_project.py` first to create the configuration.

2. **Prebuilt image pull fails**
   - Check Docker is running and has internet access
   - Verify the image exists locally (recommended) or is pullable from your registry
   - Check Docker daemon can access the registry if pulling is required

3. **Testcase doesn't crash**
   - Verify the testcase file was downloaded correctly
   - Check that ARVO prebuilt binaries are being used (not stale cache)
   - Ensure the fuzzer harness name matches ARVO metadata
   - Clear cache if needed: `rm -rf /cache/data/*/project_name/*.tar`

4. **Patching agent fails**
   - Check model configuration in `models-best.toml`
   - Verify the vulnerable function/file exists in the vulnerable version
   - Check context retrieval data for errors
   - Note: Bear build works for most ARVO projects, falls back to text-based navigation if it fails

5. **Agent produces no patch** (`failure_reason: "the agent did not produce a result"`)
   - Complex vulnerabilities (use-after-free, race conditions) may be too hard for the agent
   - Large projects (binutils-gdb, ghostpdl) may take 20+ minutes but eventually complete
   - Check if tool calls failed due to path mismatches in context_retrieval_data.json
   - Agent has 40 iteration limit - may run out before finding a solution

### Known Limitations

1. **Project Size**: Very large projects (binutils-gdb, ghostpdl, skia) can take 15-25 minutes due to extensive code exploration
2. **Complex Vulnerabilities**: Use-after-free and memory lifetime issues may be too complex for the agent to patch safely
3. **Iteration Limits**: Agent has 40 iterations for patching - may not be enough for extremely complex vulnerabilities
4. **Path Consistency**: Some ARVO images may have inconsistent WORKDIR settings (`/src` vs `/src/project`) - now handled automatically

### Debugging

1. **Check ARVO metadata**: Verify the ARVO ID exists at `https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{id}.json`
2. **Check prebuilt image**: Verify `vulpatch:{id}-vul` exists locally (or is pullable)
3. **Check testcase**: Ensure POC file was downloaded to `arvo_{id}/` directory
4. **Check project.yaml**: Ensure it was downloaded and has `main_repo` field
5. **Check logs**: Look at the detailed output from both scripts for error messages
6. **Check cache**: If using old cached builds, clear: `rm -rf /cache/data/*/project_name/*.tar`

## Workflow Examples

### Example 1: libraw vulnerability (ARVO 65027)

```bash
# Setup
python3 crs/arvo-patching-agent/setup_arvo_project.py 65027

# Run
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 65027"
```

This will:
- Pull prebuilt image `vulpatch:65027-vul` (has vulnerable libraw prebuilt)
- Extract source code and binaries from image (no build needed!)
- Test testcase `testcase_5110826180411392.bin` against vulnerable binary
- Analyze vulnerability in `libraw_tagtype_dataunit_bytes` function
- Generate patches for the vulnerable code

**Time:** ~8-10 minutes (no build time!)

### Example 2: Different ARVO ID

```bash
# Setup for different vulnerability
python3 crs/arvo-patching-agent/setup_arvo_project.py 12345

# Run
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 12345"
```

## Notes

### Using ARVO Prebuilt Images

- **Faster:** No Dockerfile build (~5-10 min saved), no compilation (~10-20 min saved)
- **Reliable:** ARVO images are pre-tested and guaranteed to work
- **Simple:** Just pull image, extract, and run

### Bear Build

- **Works for ARVO:** Bear build (generates `compile_commands.json`) now works with ARVO prebuilt images
- **How:** Preserves ARVO's environment and build state during `arvo compile`
- **Success:** Some projects (open62541) get AST-based navigation (compiler-aware, precise cross-file references)
- **Fallback:** Complex projects (wireshark) fall back to text-based navigation (regex/GTags, ~10% less precise)
- **Impact:** Better code analysis when bear succeeds, graceful degradation when it fails. Patches generate successfully either way.

### Organization

- Each ARVO ID gets its own directory to keep data organized
- The system automatically handles different projects, fuzzers, and testcases
- All outputs are saved in the ARVO-specific directory for easy analysis
- Testcases stored in arvo directories (not in project directories)
- Context retrieval data provides insights into how the patching agent works

## Contributing

When adding new features:
1. Update the configuration variables at the top of both scripts
2. Ensure directory structure remains consistent
3. Update this README with any new functionality
4. Test with multiple ARVO IDs to ensure compatibility