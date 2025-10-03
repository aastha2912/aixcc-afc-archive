# ARVO-to-CRS Integration Workflow

This directory contains scripts to automatically set up and run vulnerability analysis and patching workflows using ARVO (Automated Vulnerability Research and Operations) data with the CRS (Code Repair System).

## Overview

The system fetches vulnerability metadata from ARVO, downloads the corresponding testcase files and OSS-Fuzz project configurations, sets up the vulnerable version of the code, and runs the complete CRS workflow for vulnerability analysis and patch generation.

## Directory Structure

```
crs/arvo-patching-agent/
├── README.md                           # This file
├── setup_arvo_project.py              # Setup script (downloads metadata, testcases, project files)
├── arvo_to_crs_integration.py         # Main workflow script (runs CRS analysis and patching)
├── arvo_65027/                        # ARVO-specific directory (created automatically)
│   ├── config.json                    # Configuration for this ARVO ID
│   ├── workflow_data.json             # Complete workflow execution data
│   ├── context_retrieval_data.json    # Context retrieval calls made by patching agent
│   └── generated_patch.diff           # Generated patch (if successful)
├── arvo_12345/                        # Another ARVO ID directory
│   └── ...
└── projects/                          # Project directories (created in parent folder)
    ├── libraw/
    │   ├── Dockerfile                 # Modified to clone vulnerable version
    │   ├── Dockerfile.original        # Backup of original Dockerfile
    │   ├── build.sh                   # OSS-Fuzz build script
    │   ├── project.yaml               # OSS-Fuzz project configuration
    │   ├── libraw_fuzzer.cc           # OSS-Fuzz fuzzer harness
    │   └── testcase_5110826180411392.bin  # ARVO testcase file
    └── ...
```

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
- Download the testcase file with `testcase_` prefix
- Download OSS-Fuzz project files (Dockerfile, build.sh, project.yaml, fuzzer harness)
- Modify the Dockerfile to clone the vulnerable version (parent of fix commit)
- Create an ARVO-specific directory with configuration
- Save all configuration to `arvo_<ID>/config.json`

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
- Run the complete CRS workflow:
  1. Setup project and harnesses
  2. Test PoC and get crash result
  3. Create POVRunData from crash
  4. Decode POV
  5. Triage vulnerability with LLM
  6. Store vulnerability in database
  7. Run patching agent with context retrieval
  8. Generate patches
- Save all outputs to the ARVO-specific directory

## Detailed Workflow

### Phase 1: Project Setup (`setup_arvo_project.py`)

1. **Fetch ARVO Metadata**
   - Downloads metadata from `https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/<ARVO_ID>.json`
   - Extracts project name, fuzzer name, fix commit, testcase URL, etc.

2. **Download Testcase File**
   - Downloads the testcase from OSS-Fuzz
   - Renames with `testcase_` prefix (e.g., `testcase_5110826180411392.bin`)

3. **Download OSS-Fuzz Project Files**
   - Downloads from `https://raw.githubusercontent.com/google/oss-fuzz/master/projects/<project>`
   - Files: `Dockerfile`, `build.sh`, `project.yaml`, `<project>_fuzzer.cc`

4. **Modify Dockerfile for Vulnerable Version**
   - Changes git clone command to checkout the vulnerable commit (parent of fix commit)
   - Preserves original Dockerfile as `Dockerfile.original`

5. **Create Configuration**
   - Creates `arvo_<ID>/` directory
   - Saves configuration to `arvo_<ID>/config.json`

### Phase 2: CRS Integration (`arvo_to_crs_integration.py`)

1. **Load Configuration**
   - Reads configuration from `arvo_<ID>/config.json`
   - Sets up project directory, POC file, and fuzzer name

2. **Setup Project and Harnesses**
   - Loads the project using CRS TestProject
   - Builds the project
   - Initializes harness information
   - Finds the specified fuzzer harness

3. **Test PoC and Get Crash Result**
   - Runs the testcase against the vulnerable version
   - Captures crash output, stack trace, and deduplication ID

4. **Create POVRunData**
   - Creates POVRunData structure exactly like CRS does
   - Includes task UUID, project name, harness, sanitizer, engine, etc.

5. **Decode POV**
   - Uses CRS decode_pov function to decode the crash
   - Extracts vulnerability information

6. **Triage Vulnerability**
   - Runs CRS Triage Agent with LLM
   - Analyzes the vulnerability and identifies the vulnerable function/file

7. **Store in Database**
   - Stores vulnerability in CRS products database
   - Returns vulnerability ID for tracking

8. **Run Patching Agent**
   - Creates CRS Patcher instance
   - Runs patching agent with context retrieval
   - Captures all context retrieval calls (source_questions, read_definition, find_references, etc.)
   - Generates patches for the vulnerable code

9. **Save Outputs**
   - Saves workflow data to `arvo_<ID>/workflow_data.json`
   - Saves context retrieval data to `arvo_<ID>/context_retrieval_data.json`
   - Saves generated patch to `arvo_<ID>/generated_patch.diff`

## Configuration

### Environment Variables

The system uses the existing CRS environment variables:
- `MODEL_MAP`: Path to model configuration file (e.g., `/crs/configs/models-best.toml`)
- Database connections and other CRS settings

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
  "poc_file": "testcase_5110826180411392.bin"
}
```

### Workflow Data (`arvo_<ID>/workflow_data.json`)
Contains complete workflow execution data:
- Crash results (output, stack trace, dedup ID)
- POV run data (task UUID, project, harness, sanitizer)
- Decoded POV information
- Analyzed vulnerability (function, file, description, conditions)
- Patch results (success/failure, patch content, build artifacts)

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

2. **Project build fails**
   - Check that the Dockerfile was modified correctly
   - Verify the vulnerable commit exists in the repository
   - Check build dependencies in the OSS-Fuzz project files

3. **Testcase doesn't crash**
   - Verify the testcase file was downloaded correctly
   - Check that the vulnerable version is actually vulnerable
   - Ensure the fuzzer harness is correct

4. **Patching agent fails**
   - Check model configuration in `models-best.toml`
   - Verify the vulnerable function/file exists in the vulnerable version
   - Check context retrieval data for errors

### Debugging

1. **Check ARVO metadata**: Verify the ARVO ID exists and has the expected data
2. **Check project files**: Ensure all OSS-Fuzz files were downloaded correctly
3. **Check Dockerfile**: Verify the git clone command was modified correctly
4. **Check logs**: Look at the detailed output from both scripts for error messages

## Workflow Examples

### Example 1: libraw vulnerability (ARVO 65027)

```bash
# Setup
python3 crs/arvo-patching-agent/setup_arvo_project.py 65027

# Run
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 65027"
```

This will:
- Download libraw project files
- Set up vulnerable version (parent of commit `a6f212a4a1fe19dce1f83c83384f171fd7babb0a`)
- Test testcase `testcase_5110826180411392.bin`
- Analyze vulnerability in `libraw_tagtype_dataunit_bytes` function
- Generate patches for the vulnerable code

### Example 2: Different ARVO ID

```bash
# Setup for different vulnerability
python3 crs/arvo-patching-agent/setup_arvo_project.py 12345

# Run
docker-compose exec crs-main bash -c "source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py 12345"
```

## Notes

- Each ARVO ID gets its own directory to keep data organized
- The system automatically handles different projects, fuzzers, and testcases
- All outputs are saved in the ARVO-specific directory for easy analysis
- The vulnerable version setup ensures realistic vulnerability analysis
- Context retrieval data provides insights into how the patching agent works

## Contributing

When adding new features:
1. Update the configuration variables at the top of both scripts
2. Ensure directory structure remains consistent
3. Update this README with any new functionality
4. Test with multiple ARVO IDs to ensure compatibility

## Related Documentation

- [CRS Architecture](docs/crs-architecture.md)
- [ARVO Projects](docs/arvo-projects.md)
- [OSS-Fuzz Integration](https://github.com/google/oss-fuzz)
