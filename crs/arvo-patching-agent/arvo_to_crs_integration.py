#!/usr/bin/env python3
"""
Test PoC against different projects - Following actual CRS workflow

This script integrates ARVO vulnerability data with the CRS patching system.
It can use prebuilt ARVO Docker images to avoid rebuilding projects from source.

Prebuilt images (e.g., vulpatch:{id}-vul) contain:
  - Pre-compiled vulnerable version in /out
  - Source code in /src
  - 'vulpatch compile' command to rebuild after patching
  - 'vulpatch run' command to test with the PoC

Configuration (in arvo_<id>/config.json):
  - use_prebuilt_image: Set to true to use prebuilt ARVO images (default)
  - arvo_image_name: Docker image name (e.g., vulpatch:{id}-vul)
"""
import asyncio
import sys
import json
from pathlib import Path
import traceback
import subprocess
import hashlib
import re

# Add current directory to Python path
sys.path.insert(0, str(Path.cwd()))

from crs.modules.project import Harness, HarnessType
from crs.modules.testing import TestProject

# =============================================================================
# CONFIGURATION
# =============================================================================

# Directory structure (must match setup_arvo_project.py)
ARVO_CONFIG_DIR_NAME = "arvo_{arvo_id}"  # Directory name for ARVO configurations
ARVO_CONFIG_FILE_NAME = "config.json"    # Configuration file name

# =============================================================================
# CONFIGURATION LOADING
# =============================================================================

def load_arvo_config(arvo_id: str) -> dict:
    """Load configuration from ARVO config file"""
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    config_file = arvo_dir / ARVO_CONFIG_FILE_NAME
    
    if not config_file.exists():
        print(f"Configuration file not found: {config_file}")
        print("Please run setup_arvo_project.py first to create the configuration.")
        sys.exit(1)

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)


def load_metadata_entry(arvo_id: str) -> dict:
    """Load metadata for a given ARVO ID from the mounted /crs/metadata.json."""
    metadata_path = Path("/crs/metadata.json")
    if not metadata_path.exists():
        raise RuntimeError(f"Required metadata file not found: {metadata_path}")

    try:
        metadata = json.loads(metadata_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise RuntimeError(f"Error loading metadata file {metadata_path}: {e}") from e

    entry = metadata.get(str(arvo_id))
    if entry is None:
        raise RuntimeError(f"No metadata entry found for ARVO ID {arvo_id} in {metadata_path}")
    return entry

def resolve_fuzzer_name(entry: dict, config: dict | None = None) -> str:
    """Resolve the harness/fuzzer target name, preferring metadata.json and falling back to config.json."""
    for source_name, source in (("metadata.json", entry), ("config.json", config or {})):
        for key in ("fuzzer_name", "harness_name", "target_name"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        command = source.get("command")
        if isinstance(command, str) and command.strip():
            first = command.strip().split()[0]
            if first:
                return Path(first).name

    raise RuntimeError(
        "Neither metadata.json nor config.json contains a usable harness target. "
        "Expected one of: fuzzer_name, harness_name, target_name, or command."
    )


def extract_command_target(entry: dict) -> str | None:
    """Extract the executable basename from metadata.json command."""
    command = entry.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    first = command.strip().split()[0]
    return Path(first).name or None

def get_config_from_args():
    """Get configuration from command line arguments"""
    if len(sys.argv) < 2:
        print("Usage: python3 arvo_to_crs_integration.py <ARVO_ID>")
        print("Example: python3 arvo_to_crs_integration.py 65027")
        sys.exit(1)
    
    arvo_id = sys.argv[1]
    config = load_arvo_config(arvo_id)
    metadata = load_metadata_entry(arvo_id)
    resolved_fuzzer_name = resolve_fuzzer_name(metadata, config)
    
    print(f"\nLoaded configuration for ARVO ID: {arvo_id}")
    print(f"Project: {config['project_name']}")
    print(f"Fuzzer: {resolved_fuzzer_name}")
    print(f"POC File: {config['poc_file']}")
    print("="*60)
    config["_resolved_fuzzer_name"] = resolved_fuzzer_name
    return config

# Load configuration from command line arguments
CONFIG = get_config_from_args()
METADATA = load_metadata_entry(CONFIG["arvo_id"])

# Extract configuration parameters
PROJECT_DIR = CONFIG['project_dir']
POC_FILE = CONFIG['poc_file']
FUZZER_NAME = CONFIG['_resolved_fuzzer_name']

# =============================================================================
# END CONFIGURATION LOADING
# =============================================================================

def pull_arvo_image_if_needed(arvo_image_name: str) -> bool:
    """
    Ensure the prebuilt image exists in the active Docker daemon.
    
    NOTE: In this stack CRS typically talks to a DinD daemon (via DOCKER_HOST),
    which does NOT share images with the host Docker daemon. This function does
    not attempt to import from the host daemon. If the image is missing, load it
    into DinD first (see README helper script).
    
    Returns:
        True if image is available
        False if unavailable
    """
    print("Checking for ARVO image...")
    proc_check = subprocess.run(
        ["docker", "image", "inspect", arvo_image_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if proc_check.returncode == 0:
        print("ARVO image already exists locally")
        return True

    print(f"Prebuilt image not present in active Docker daemon: {arvo_image_name}")
    print("Load it into DinD first (see crs/arvo-patching-agent/load_images_into_dind.sh).")
    return False


async def extract_arvo_source_and_workdir(arvo_image_name: str, project_name: str, ossfuzz_hash: str):
    """
    Extract source code from ARVO image and save workdir marker.
    
    This creates:
    - src.tar: Source code from ARVO /src (CRS will skip Dockerfile build)
    - arvo_workdir.txt: Workdir marker (signals ARVO mode to project.py)
    
    Returns:
        True if extraction succeeded, False otherwise
    """
    from pathlib import Path as StdPath
    from crs import config
    from crs.common import docker
    
    # Calculate cache directory (same logic as TestProject.from_dir)
    data_dir = StdPath(config.CACHE_DIR) / "data" / ossfuzz_hash / project_name
    data_dir.mkdir(parents=True, exist_ok=True)
    
    src_tar_path = data_dir / "src.tar"
    workdir_marker = data_dir / "arvo_workdir.txt"
    
    # Get workdir from ARVO image metadata
    # This is needed because we won't build the Dockerfile to get it
    print(f"Getting workdir from ARVO image...")
    async with docker.scope(timeout=120) as scope:
        workdir_result = await docker.get_image_workdir(scope, arvo_image_name)
        if workdir_result.is_err():
            print(f"Failed to get workdir from ARVO image: {workdir_result.err()}")
            return False
        
        workdir = workdir_result.unwrap()
        # Save workdir marker - tells project.py we're in ARVO mode
        with open(workdir_marker, "w") as f:
            f.write(workdir)
        print(f"Saved ARVO workdir marker: {workdir}")
    
    # Extract /src from ARVO image if not already cached
    if not src_tar_path.exists():
        print(f"Extracting source code from ARVO image to {src_tar_path}...")
        try:
            async with docker.run(arvo_image_name, timeout=600, group=docker.DockerGroup.Misc) as run:
                # Stream directly to file to avoid memory issues with huge projects
                with open(src_tar_path, "wb") as f:
                    proc = await run.exec(
                        "tar", "cf", "-", "--transform", r"s/^\.\///", "-C", "/src", ".",
                        stdout=f,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    _, stderr = await proc.communicate()
                
                if proc.returncode != 0:
                    print(f"Failed to extract /src: {stderr.decode(errors='replace')[:200]}")
                    if src_tar_path.exists():
                        src_tar_path.unlink()
                    return False
                
                if not src_tar_path.exists() or src_tar_path.stat().st_size == 0:
                    print(f"ERROR: No data extracted from /src")
                    return False
                
                size_mb = src_tar_path.stat().st_size / (1024 * 1024)
                print(f"Extracted source code from ARVO image ({size_mb:.1f} MB)")
                print(f"CRS will detect src.tar and skip Dockerfile build entirely")
        except asyncio.TimeoutError:
            print(f"ERROR: Source extraction timed out (600s)")
            return False
        except Exception as e:
            print(f"ERROR: Source extraction failed: {e}")
            return False
    else:
        print(f"Source code already cached at {src_tar_path}")
    
    return True


async def extract_arvo_binaries(task, arvo_image_name: str) -> bool:
    """
    Extract prebuilt binaries from ARVO /out directory.
    
    For each build config (address sanitizer, undefined sanitizer, etc.),
    extracts the prebuilt fuzzers and saves to CRS's build cache.
    
    Returns:
        True if extraction succeeded, False otherwise
    """
    from crs.common import docker
    from crs.common.types import Ok, Err
    
    print(f"\nExtracting prebuilt binaries (/out) from ARVO image...")
    
    try:
        async with docker.scope(timeout=300) as scope:
            # Extract build artifacts for each build config
            # ARVO images have the vulnerable version already compiled in /out
            for build_config in task.project.info.build_configs:
                # Get the expected tar path for this build config
                # CRS checks if this exists to skip compilation
                build_tar_path = await task.project.get_build_tar(build_config)
                
                # Skip if we already have this build cached
                if await build_tar_path.exists():
                    print(f"Build artifacts for {build_config.SANITIZER} already cached at {build_tar_path}")
                    continue
                
                # Run a container from the ARVO image and copy /out directory
                async with docker.run(arvo_image_name, timeout=120, group=docker.DockerGroup.Misc) as run:
                    # Stream directly to file to avoid memory issues
                    with open(build_tar_path, "wb") as f:
                        proc = await run.exec(
                            "tar", "cf", "-", "--transform", r"s/^\.\///", "-C", "/out", ".",
                            stdout=f,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        _, stderr = await proc.communicate()
                    
                    if proc.returncode != 0:
                        print(f"Failed to extract /out: {stderr.decode(errors='replace')[:200]}")
                        if await build_tar_path.exists():
                            await build_tar_path.unlink()
                        return False
                    
                    if not await build_tar_path.exists() or (await build_tar_path.stat()).st_size == 0:
                        print(f"ERROR: No binaries extracted for {build_config.SANITIZER}")
                        return False
                    
                    size_mb = (await build_tar_path.stat()).st_size / (1024 * 1024)
                    print(f"Extracted prebuilt binaries for {build_config.SANITIZER} ({size_mb:.1f} MB)")
            
            print("\n✓ Successfully setup from ARVO prebuilt image:")
            print("  - Source code extracted from /src (Dockerfile build skipped)")
            print("  - Binaries extracted from /out (compilation skipped)")
            print("  - Context retrieval and patching will use ARVO vulnerable version")
            return True
    
    except Exception as e:
        print(f"Error extracting binaries from ARVO image: {e}")
        import traceback
        traceback.print_exc()
        return False


def find_fuzzer_index(harness_list, fuzzer_name: str) -> int:
    """
    Find the index of the specified fuzzer in the harness list.
    
    Returns:
        Index of the fuzzer, or None if not found
    """
    harness_names = [h.name for h in harness_list]
    
    for i, name in enumerate(harness_names):
        if name == fuzzer_name:
            return i
    
    return None


def normalize_harness_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def tokenize_harness_name(value: str) -> set[str]:
    stop_words = {
        "afl",
        "file",
        "for",
        "fuzz",
        "fuzzer",
        "honggfuzz",
        "input",
        "libfuzzer",
        "one",
        "target",
    }
    return {
        token
        for token in re.split(r"[^a-z0-9]+", value.lower())
        if token and token not in stop_words
    }


def infer_source_from_metadata(metadata_entry: dict) -> str:
    """Use the first /src path from the sanitizer report as a source hint."""
    report = metadata_entry.get("sanitizer_report")
    if isinstance(report, str):
        match = re.search(r"/src/([^\s:]+)", report)
        if match:
            return match.group(1)
    return "unknown.c"


def build_runtime_harness(
    harness_list,
    metadata_entry: dict,
    requested_name: str,
) -> tuple[list, int, str]:
    """
    Build a canonical harness entry whose name matches the real ARVO executable.

    CRS discovery is still used for source/options/context when available, but
    downstream execution should always use the runtime target from metadata.
    """
    runtime_name = extract_command_target(metadata_entry) or requested_name
    if not runtime_name:
        raise RuntimeError("Unable to determine runtime harness target from metadata")

    exact_index = find_fuzzer_index(harness_list, runtime_name)
    if exact_index is not None:
        return harness_list, exact_index, "exact CRS harness match"

    candidates = []
    for raw_name in {requested_name, runtime_name}:
        if not raw_name:
            continue
        normalized = normalize_harness_name(raw_name)
        tokens = tokenize_harness_name(raw_name)
        candidates.append((raw_name, normalized, tokens))

    matched_harness = None
    match_reason = "synthetic runtime harness"

    for harness in harness_list:
        harness_norm = normalize_harness_name(harness.name)
        if any(harness_norm == normalized for _, normalized, _ in candidates):
            matched_harness = harness
            match_reason = f"normalized name match to CRS harness '{harness.name}'"
            break

    if matched_harness is None:
        scored_matches: list[tuple[int, int, object]] = []
        for index, harness in enumerate(harness_list):
            harness_tokens = tokenize_harness_name(harness.name)
            harness_tokens |= tokenize_harness_name(Path(harness.source).stem)
            overlap = max(
                len(tokens & harness_tokens)
                for _, _, tokens in candidates
            ) if candidates else 0
            if overlap > 0:
                scored_matches.append((overlap, -index, harness))

        if scored_matches:
            scored_matches.sort(reverse=True)
            best_overlap, _, best_harness = scored_matches[0]
            if len(scored_matches) == 1 or best_overlap > scored_matches[1][0]:
                matched_harness = best_harness
                match_reason = (
                    f"token-overlap match to CRS harness '{best_harness.name}' "
                    f"(score={best_overlap})"
                )

    if matched_harness is not None:
        runtime_harness = Harness(
            name=runtime_name,
            type=matched_harness.type,
            source=matched_harness.source,
            options=matched_harness.options,
            harness_func=matched_harness.harness_func,
        )
    else:
        runtime_harness = Harness(
            name=runtime_name,
            type=HarnessType.LIBFUZZER,
            source=infer_source_from_metadata(metadata_entry),
            options="",
            harness_func=None,
        )

    for index, harness in enumerate(harness_list):
        if harness.name == runtime_harness.name:
            updated = list(harness_list)
            updated[index] = runtime_harness
            return updated, index, match_reason

    updated = list(harness_list) + [runtime_harness]
    return updated, len(updated) - 1, match_reason


async def setup_project_and_harnesses():
    """
    Phase 1: Setup project and find harnesses using ARVO prebuilt image.
    
    This function orchestrates the setup process:
    1. Pull ARVO prebuilt Docker image if needed
    2. Extract source code from ARVO /src (skips Dockerfile build)
    3. Extract binaries from ARVO /out (skips compilation)
    4. Load project using CRS (which finds our cached extracts)
    5. Initialize harnesses and find the target fuzzer
    
    Returns:
        (task, harness_list, fuzzer_index) if successful
        (None, None, None) if setup failed
    """
    print("\n" + "="*60)
    print("PHASE 1: SETTING UP PROJECT AND HARNESSES")
    print("="*60)
    print(f"Configuration:")
    print(f"  Project: {PROJECT_DIR}")
    print(f"  POC File: {POC_FILE}")
    print(f"  Fuzzer: {FUZZER_NAME}")
    
    # =========================================================================
    # Step 1: Check configuration and prepare for ARVO prebuilt mode
    # =========================================================================
    use_prebuilt_image = CONFIG.get('use_prebuilt_image', True)
    arvo_image_name = CONFIG.get('arvo_image_name', None)

    if not use_prebuilt_image:
        raise RuntimeError(
            "Prebuilt-image-only mode: config has use_prebuilt_image=false. "
            "Set use_prebuilt_image=true and provide arvo_image_name."
        )
    if not arvo_image_name:
        raise RuntimeError(
            "Prebuilt-image-only mode: missing arvo_image_name in config.json. "
            "Set arvo_image_name to your prebuilt image (e.g., vulpatch:<id>-vul)."
        )

    print(f"  Using prebuilt ARVO image: {arvo_image_name}")
    print("="*60)
    
    prebuilt_setup_done = False
    
    # =========================================================================
    # Step 2: Pull ARVO Docker image if using prebuilt mode
    # =========================================================================
    if use_prebuilt_image and arvo_image_name:
        print(f"Attempting to use prebuilt ARVO image: {arvo_image_name}")
        print("This will extract both /src (source code) and /out (binaries) to skip Dockerfile build")
        
        # Pull image using helper function
        if not pull_arvo_image_if_needed(arvo_image_name):
            raise RuntimeError(
                f"Prebuilt-image-only mode: failed to fetch prebuilt image {arvo_image_name!r}. "
                "Ensure it exists locally (docker image inspect) or is pullable (docker login / registry access)."
            )
        
        # =====================================================================
        # Step 3: Extract source code and workdir from ARVO image
        # =====================================================================
        if use_prebuilt_image:
            try:
                # Calculate ossfuzz_hash - needed to determine cache location
                # This must match what TestProject.from_dir() calculates
                from pathlib import Path as StdPath
                import hashlib
                import subprocess
                
                projects_dir = StdPath(PROJECT_DIR).parent
                
                # Get git hash and diff of projects directory
                proc_hash = subprocess.run(
                    ["git", "-C", str(projects_dir.absolute()), "log", "-1", "--pretty=format:'%H'", str(projects_dir.absolute())],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                git_hash = proc_hash.stdout
                
                proc_diff = subprocess.run(
                    ["git", "-C", str(projects_dir.absolute()), "diff", str(projects_dir.absolute())],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                git_diff = proc_diff.stdout
                
                # Calculate hash - this determines cache directory
                h = hashlib.sha256()
                h.update(git_hash)
                h.update(git_diff)
                ossfuzz_hash = h.hexdigest()
                
                project_name = StdPath(PROJECT_DIR).name
                
                # Extract source and workdir using helper function
                if await extract_arvo_source_and_workdir(arvo_image_name, project_name, ossfuzz_hash):
                    prebuilt_setup_done = True
                else:
                    raise RuntimeError(
                        f"Prebuilt-image-only mode: failed to extract /src or workdir from {arvo_image_name!r}."
                    )
                    
            except Exception as e:
                raise RuntimeError(f"Prebuilt-image-only mode: error during prebuilt setup: {e}") from e
    
    # =========================================================================
    # Step 4: Load project using CRS
    # =========================================================================
    # At this point, if we extracted src.tar, CRS will find it and skip Dockerfile build
    project = await TestProject.from_dir(PROJECT_DIR)
    task = await project.task()
    
    # =========================================================================
    # Step 5: Override build_image to use ARVO container for all operations
    # =========================================================================
    # CRS generates image names like "libraw:abc123" which don't exist
    # We override to use ARVO image which has everything
    if use_prebuilt_image and arvo_image_name and prebuilt_setup_done:
        print(f"Setting build_image to ARVO image: {arvo_image_name}")
        task.project.build_image = arvo_image_name
        print(f"All build operations will now use ARVO prebuilt image")
    else:
        raise RuntimeError("Prebuilt-image-only mode: internal error (prebuilt_setup_done was false).")
    
    # =========================================================================
    # Step 6: Extract prebuilt binaries from ARVO /out
    # =========================================================================
    # Extract fuzzers for each sanitizer (address, undefined, etc.)
    if use_prebuilt_image and arvo_image_name and prebuilt_setup_done:
        if not await extract_arvo_binaries(task, arvo_image_name):
            raise RuntimeError(
                f"Prebuilt-image-only mode: failed to extract /out binaries from {arvo_image_name!r}."
            )
    
    # =========================================================================
    # Step 7: Initialize harnesses (CRS scans binaries to find fuzzers)
    # =========================================================================
    # Note: init_harness_info() calls build_all() internally
    # Since we pre-populated build caches, it will use those instead of compiling
    print("Initializing harnesses...")
    harnesses = await task.project.init_harness_info()
    if harnesses.is_err():
        print(f"Harness initialization failed: {harnesses.err()}")
        return None, None, None
    
    harness_list = harnesses.unwrap()
    print(f"Found {len(harness_list)} harnesses:")
    harness_names = [h.name for h in harness_list]
    for i, name in enumerate(harness_names):
        print(f"  {i}: {name}")
    
    # =========================================================================
    # Step 8: Find the fuzzer specified in configuration
    # =========================================================================
    harness_list, fuzzer_index, resolution_reason = build_runtime_harness(
        harness_list,
        METADATA,
        FUZZER_NAME,
    )
    task.project.harnesses = harness_list

    print(f"Resolved runtime harness: {harness_list[fuzzer_index].name} (index {fuzzer_index})")
    print(f"Resolution reason: {resolution_reason}")
    if harness_list[fuzzer_index].source:
        print(f"Harness source hint: {harness_list[fuzzer_index].source}")
    
    return task, harness_list, fuzzer_index


def prepare_poc_data():
    """Prepare PoC data for testing"""
    # Check if you have a real PoC file
    # POC_FILE is already a full path from workspace root, don't join with PROJECT_DIR
    poc_file = Path(POC_FILE)
    if poc_file.exists():
        print(f"Found PoC file: {poc_file}")
        # Read the PoC file and embed it directly in the Python script
        with open(poc_file, "rb") as f:
            poc_data = f.read()
        print(f"Read {len(poc_data)} bytes from PoC file")
        
        # Embed the data directly in the Python script
        pov_python = f"""
# Use embedded PoC data
poc_data = {repr(poc_data)}

with open("input.bin", "wb") as f:
    f.write(poc_data)
"""
    else:
        print("No PoC file found, using test data")
        # Use embedded test data
        pov_python = """
# Create test PoC data and write it as input.bin
poc_data = b"test poc data that might trigger a vulnerability"

with open("input.bin", "wb") as f:
    f.write(poc_data)
"""
    
    return pov_python


def normalize_stack_line(line: str) -> str:
    """Normalize paths in sanitizer stack traces to match CRS VFS paths."""
    return line.replace(" /src/", " ")


def extract_stack_and_dedup(report_text: str) -> tuple[str, str]:
    """Extract normalized stack trace and dedup token from a sanitizer report."""
    stack_lines: list[str] = []
    dedup_token = None

    for line in report_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            stack_lines.append(normalize_stack_line(stripped))
        elif "DEDUP_TOKEN:" in line and dedup_token is None:
            dedup_token = line.split("DEDUP_TOKEN:", 1)[1].strip()

    if not stack_lines:
        raise RuntimeError("No stack trace found in sanitizer report")

    stack = "\n".join(stack_lines)
    if not dedup_token:
        dedup_token = hashlib.sha256(stack.encode()).hexdigest()

    return stack, dedup_token


def resolve_build_config(task, sanitizer_name: str | None):
    """Pick the build config matching the sanitizer from metadata/config, else use default."""
    if sanitizer_name:
        for build_config in task.project.info.build_configs:
            if build_config.SANITIZER == sanitizer_name:
                return build_config
    return task.project.info.default_build_config


async def run_arvo_and_capture_crash(arvo_image_name: str, testcase_path: Path, fuzzer_name: str) -> str:
    """
    Run ARVO to test the PoC and capture the crash output.
    
    This uses ARVO's prebuilt vulnerable binary, avoiding the rebuild problem.
    
    Args:
        arvo_image_name: Prebuilt vulnerable Docker image (e.g., "vulpatch:65027-vul")
        testcase_path: Path to PoC testcase file
        fuzzer_name: Name of the fuzzer to run
    
    Returns:
        Raw output from ARVO run including crash info
    """
    from crs.common import docker
    import asyncio
    
    print("Running ARVO to get authentic crash...")
    print(f"  Image: {arvo_image_name}")
    print(f"  Fuzzer: {fuzzer_name}")
    print(f"  Testcase: {testcase_path}")
    
    try:
        # Read testcase data
        with open(testcase_path, 'rb') as f:
            testcase_data = f.read()
        
        # Run ARVO container
        async with docker.run(arvo_image_name, timeout=120, group=docker.DockerGroup.Misc) as run:
            # Write testcase to container
            from crs.common.docker import vwrite
            from crs.common.types import Ok, Err
            result = await vwrite(run, {"/testcase": testcase_data})
            if result.is_err():
                print(f"Failed to write testcase: {result.err()}")
                return ""
            
            # Run ARVO reproduce command
            proc = await run.exec("arvo", "run", fuzzer_name, "/testcase", 
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.STDOUT)
            stdout, _ = await proc.communicate()
            output = stdout.decode(errors='replace')
            
            print("✓ ARVO run completed")
            return output
            
    except Exception as e:
        print(f"Error running ARVO: {e}")
        import traceback
        traceback.print_exc()
        return ""


async def create_crash_result_from_arvo(task, harness_list, fuzzer_index, arvo_crash_output: str):
    """
    Phase 2: Create CrashResult directly from ARVO run output.
    
    This bypasses the CRS test_pov() which would rebuild binaries and potentially
    trigger a different crash. Instead, we use the authentic ARVO crash data.
    
    Args:
        arvo_crash_output: Raw output from 'arvo run' command containing crash info
    
    Returns:
        (crash_result, pov_python) tuple
    """
    print("\n" + "="*60)
    print("PHASE 2: CREATING CrashResult FROM ARVO OUTPUT")
    print("="*60)
    print("Skipping CRS test_pov() to avoid rebuilding binaries")
    print("Using authentic ARVO crash data instead")
    
    from crs.modules.project import CrashResult
    from crs.common.types import BuildConfig
    
    try:
        stack, dedup_token = extract_stack_and_dedup(arvo_crash_output)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        return None, None

    build_config = resolve_build_config(task, CONFIG.get("sanitizer"))
    
    # Prepare POV python script
    pov_python = prepare_poc_data()
    
    # Create CrashResult matching CRS format
    crash_result = CrashResult(
        config=build_config,
        input=b"",  # Not needed for triage
        output=arvo_crash_output,  # Full ARVO output
        dedup=dedup_token,
        stack=stack
    )
    
    print("✓ Created CrashResult from ARVO data:")
    print(f"  Dedup: {crash_result.dedup[:80]}...")
    print(f"  Stack frames: {len(stack.splitlines())}")
    print(f"  Stack preview: {stack[:200]}...")
    
    return crash_result, pov_python


async def create_crash_result_from_metadata_report(task, metadata_entry: dict):
    """
    Phase 2: Create CrashResult directly from sanitizer report text in metadata.json.
    """
    print("\n" + "="*60)
    print("PHASE 2: CREATING CrashResult FROM METADATA SANITIZER REPORT")
    print("="*60)
    print("Skipping prebuilt-image crash reproduction")
    print("Using sanitizer report from metadata.json")

    from crs.modules.project import CrashResult

    report_text = metadata_entry.get("sanitizer_report")
    if not report_text:
        raise RuntimeError("metadata.json entry is missing 'sanitizer_report'")

    stack, dedup_token = extract_stack_and_dedup(report_text)
    build_config = resolve_build_config(
        task,
        metadata_entry.get("sanitizer_type") or CONFIG.get("sanitizer"),
    )
    pov_python = prepare_poc_data()

    crash_result = CrashResult(
        config=build_config,
        input=b"",
        output=report_text,
        dedup=dedup_token,
        stack=stack,
    )

    print("✓ Created CrashResult from metadata report:")
    print(f"  Dedup: {crash_result.dedup[:80]}...")
    print(f"  Stack frames: {len(stack.splitlines())}")
    print(f"  Stack preview: {stack[:200]}...")

    return crash_result, pov_python


async def test_poc_crash(task, harness_list, fuzzer_index):
    """Phase 2: Test PoC and get crash result"""
    print("\n" + "="*60)
    print("PHASE 2: TESTING POC")
    print("="*60)
    
    pov_python = prepare_poc_data()
    
    # Test PoC (EXACTLY like CRS does)
    print("Testing PoC...")
    result = await task.test_pov(harness_num=fuzzer_index, pov_python=pov_python)
    
    if result.is_err():
        print("PoC did not crash")
        print(f"Error: {result.err()}")
        return None, None
    
    crash_result = result.unwrap()
    print("PoC triggered a crash!")
    print(f"Output: {crash_result.output[:200]}...")
    print(f"Stack: {crash_result.stack[:200]}...")
    print(f"Dedup: {crash_result.dedup}")
    
    return crash_result, pov_python


async def create_pov_run_data(task, harness_list, fuzzer_index, crash_result, pov_python):
    """Phase 3: Create POVRunData from crash"""
    print("\n" + "="*60)
    print("PHASE 3: CREATING POVRunData FROM CRASH")
    print("="*60)
    
    from crs.common.types import POVRunData
    
    # Create POVRunData EXACTLY like CRS does in handle_pov_produce_result (line 1201-1213)
    pov_run_data = POVRunData(
        task_uuid=task.task_id,  # Use actual task UUID
        project_name=task.project.name,  # Use actual project name
        harness=harness_list[fuzzer_index].name,
        sanitizer=crash_result.config.SANITIZER,
        engine=crash_result.config.FUZZING_ENGINE,
        python=pov_python,
        input=crash_result.input,  # Use actual input from crash
        output=crash_result.output,
        dedup=crash_result.dedup,
        stack=crash_result.stack
    )
    
    print(f"Created POVRunData (like CRS does):")
    print(f"  Task UUID: {pov_run_data.task_uuid}")
    print(f"  Project: {pov_run_data.project_name}")
    print(f"  Harness: {pov_run_data.harness}")
    print(f"  Sanitizer: {pov_run_data.sanitizer}")
    print(f"  Dedup: {pov_run_data.dedup}")
    
    return pov_run_data


async def decode_pov(task, harness_list, pov_run_data):
    """Phase 4: Decode POV"""
    print("\n" + "="*60)
    print("PHASE 4: DECODING POV")
    print("="*60)
    
    # Create CRS instance to use decode_pov method (like CRS does in triage_pov line 1186)
    from crs.app.app import CRS
    
    crs_instance = CRS()
    print("Decoding POV using CRS decode_pov function...")
    decoded_pov, _ = await crs_instance.decode_pov(task, harness_list, pov_run_data)
    
    print(f"Decoded POV:")
    print(f"  Project: {decoded_pov.project_name}")
    print(f"  Harness: {decoded_pov.harness}")
    print(f"  Decoding: {decoded_pov.decoding[:200]}...")
    print(f"  Dedup: {decoded_pov.dedup}")
    
    return decoded_pov, crs_instance


async def triage_vulnerability(task, decoded_pov):
    """Phase 5: Triage vulnerability with LLM"""
    print("\n" + "="*60)
    print("PHASE 5: TRIAGING POV WITH LLM")
    print("="*60)
    
    from crs.agents.triage import CRSTriage
    
    # Run triage EXACTLY like CRS does in triage_pov (line 1191)
    print("Running CRS Triage Agent (with context retrieval)...")
    triage_agent = CRSTriage.from_task(task)
    analyzed_vuln_result = await triage_agent.pov_triage(decoded_pov)
    
    if analyzed_vuln_result.is_err():
        print(f"CRS Triage Agent failed: {analyzed_vuln_result.err()}")
        return None, None
    
    analyzed_vuln = analyzed_vuln_result.unwrap()
    print(f"Vulnerability Analysis Complete:")
    print(f"  Function: {analyzed_vuln.function}")
    print(f"  File: {analyzed_vuln.file}")
    print(f"  Description: {analyzed_vuln.description[:200]}...")
    print(f"  Conditions: {len(analyzed_vuln.conditions)} conditions")
    
    # Get LLM cost data from triage agent
    llm_calls = triage_agent.get_llm_calls()
    total_cost = sum(call.get('cost', 0) for call in llm_calls)
    total_input_tokens = sum(call.get('input_tokens', 0) for call in llm_calls)
    total_output_tokens = sum(call.get('output_tokens', 0) for call in llm_calls)
    
    print(f"\nTriage Agent Cost Analysis:")
    print(f"  Total LLM calls: {len(llm_calls)}")
    print(f"  Total cost: ${total_cost:.4f}")
    print(f"  Total input tokens: {total_input_tokens}")
    print(f"  Total output tokens: {total_output_tokens}")
    
    return analyzed_vuln, llm_calls


async def store_vulnerability_in_database(crs_instance, task, analyzed_vuln):
    """Phase 6: Store vulnerability in database"""
    print("\n" + "="*60)
    print("PHASE 6: STORING VULNERABILITY IN DATABASE")
    print("="*60)
    
    # Store vulnerability in database EXACTLY like CRS does in handle_analyzed_vuln
    from crs.app.app import VulnSource
    
    # Use the CRS instance's productsdb (like CRS does)
    print("Storing vulnerability in database...")
    vuln_id = await crs_instance.productsdb.add_vuln(
        task=task.task_id,
        project=task.project.name,
        vuln=analyzed_vuln,
        source="arvo_poc_test",  # Source identifier
        report_id=None,
        sarif_id=None
    )
    
    print(f"Vulnerability stored in database with ID: {vuln_id}")
    print(f"  Vuln ID: {vuln_id}")
    print(f"  Function: {analyzed_vuln.function}")
    print(f"  File: {analyzed_vuln.file}")
    
    return vuln_id


def save_workflow_data(vuln_id, crash_result, pov_run_data, decoded_pov, analyzed_vuln, arvo_id, triage_llm_calls):
    """Phase 7: Save workflow data"""
    print("\n" + "="*60)
    print("PHASE 7: SAVING WORKFLOW DATA")
    print("="*60)
    
    workflow_data = {
        "vuln_id": vuln_id,  # Database ID for the stored vulnerability
        "crash_result": {
            "output": crash_result.output[:500],
            "stack": crash_result.stack.decode('utf-8', errors='replace')[:500] if isinstance(crash_result.stack, bytes) else crash_result.stack[:500],
            "dedup": crash_result.dedup
        },
        "pov_run_data": {
            "task_uuid": str(pov_run_data.task_uuid),
            "project_name": pov_run_data.project_name,
            "harness": pov_run_data.harness,
            "sanitizer": pov_run_data.sanitizer,
            "engine": pov_run_data.engine,
            "dedup": pov_run_data.dedup
        },
        "decoded_pov": {
            "project_name": decoded_pov.project_name,
            "harness": decoded_pov.harness,
            "sanitizer": decoded_pov.sanitizer,
            "engine": decoded_pov.engine,
            "decoding": decoded_pov.decoding,
            "dedup": decoded_pov.dedup
        },
        "analyzed_vuln": {
            "function": analyzed_vuln.function,
            "file": analyzed_vuln.file,
            "description": analyzed_vuln.description,
            "conditions": analyzed_vuln.conditions
        },
        "cost_analysis": {
            "triage": {
                "total_llm_calls": len(triage_llm_calls),
                "total_cost": sum(call.get('cost', 0) for call in triage_llm_calls),
                "total_input_tokens": sum(call.get('input_tokens', 0) for call in triage_llm_calls),
                "total_output_tokens": sum(call.get('output_tokens', 0) for call in triage_llm_calls),
                "total_cached_tokens": sum(call.get('cached_tokens', 0) for call in triage_llm_calls),
                "llm_calls": triage_llm_calls
            }
        }
    }
    
    # Save to ARVO-specific directory
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    workflow_file = arvo_dir / "workflow_data.json"
    workflow_file.write_text(json.dumps(workflow_data, indent=2))
    print(f"Saved workflow data to: {workflow_file}")
    
    return workflow_data, workflow_file


def save_failure_data(arvo_id: str, phase: str, exc: BaseException) -> Path:
    """
    Save failure details to arvo_<ID>/workflow_data.json so failures are trackable
    the same way successes are.
    """
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    arvo_dir.mkdir(parents=True, exist_ok=True)
    workflow_file = arvo_dir / "workflow_data.json"

    failure_data = {
        "status": "failed",
        "phase": phase,
        "error_type": exc.__class__.__name__,
        "error": str(exc),
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        "config": {
            "arvo_id": CONFIG.get("arvo_id"),
            "project_dir": CONFIG.get("project_dir"),
            "project_name": CONFIG.get("project_name"),
            "fuzzer_name": CONFIG.get("fuzzer_name"),
            "poc_file": CONFIG.get("poc_file"),
            "arvo_image_name": CONFIG.get("arvo_image_name"),
            "use_prebuilt_image": CONFIG.get("use_prebuilt_image"),
        },
    }

    workflow_file.write_text(json.dumps(failure_data, indent=2))
    print(f"Saved failure data to: {workflow_file}")
    return workflow_file


async def run_patching_agent(task, analyzed_vuln, decoded_pov, vuln_id, workflow_data, workflow_file, arvo_id):
    """Phase 8: Run patching agent"""
    print("\n" + "="*60)
    print("PHASE 8: RUNNING PATCHING AGENT")
    print("="*60)
    
    # Run the patching agent EXACTLY like CRS does in patch_vuln
    from crs.agents.produce_patch import CRSPatcher
    
    print("Starting CRS Patching Agent...")
    print(f"  Vulnerability ID: {vuln_id}")
    print(f"  Function: {analyzed_vuln.function}")
    print(f"  File: {analyzed_vuln.file}")
    
    # Create CRS Patcher instance (like CRS does)
    patcher = CRSPatcher.from_task(task)
    
    # Get POVs for this vulnerability (we have our decoded_pov)
    povs = [decoded_pov]  # Use the POV we already have
    
    print("Patching Agent will use context retrieval tools:")
    print("  source_questions - Ask natural language questions about code")
    print("  read_definition - Read function definitions")
    print("  read_source - Read source code")
    print("  find_references - Find function references")
    print("  apply_patch - Apply patches to code")
    print("  test_patch - Test patches against PoC")
    
    try:
        # Run the patching agent EXACTLY like CRS does in patch_vuln
        print("\nRunning patching agent (this may take a while)...")
        patch_result = await patcher.patch_vulnerability(
            analyzed_vuln, 
            povs, 
            rawdiff=False  # Use structured diff format
        )
        
        if patch_result.is_ok():
            patch_response = patch_result.unwrap()
            print(f"Patching agent completed!")
            print(f"  Success: {patch_response.success}")
            
            # Get context capture data from the patching agent
            context_capture = patcher.get_context_capture() if hasattr(patcher, 'get_context_capture') else {}
            last_validation = patcher.get_last_validation() if hasattr(patcher, 'get_last_validation') else None
            
            # Get LLM cost data from patching agent
            patching_llm_calls = patcher.get_llm_calls() if hasattr(patcher, 'get_llm_calls') else []
            total_patch_cost = sum(call.get('cost', 0) for call in patching_llm_calls)
            total_patch_input_tokens = sum(call.get('input_tokens', 0) for call in patching_llm_calls)
            total_patch_output_tokens = sum(call.get('output_tokens', 0) for call in patching_llm_calls)
            
            print(f"\nPatching Agent Cost Analysis:")
            print(f"  Total LLM calls: {len(patching_llm_calls)}")
            print(f"  Total cost: ${total_patch_cost:.4f}")
            print(f"  Total input tokens: {total_patch_input_tokens}")
            print(f"  Total output tokens: {total_patch_output_tokens}")
            
            # Add patching cost to workflow data
            if "cost_analysis" not in workflow_data:
                workflow_data["cost_analysis"] = {}
            workflow_data["cost_analysis"]["patching"] = {
                "total_llm_calls": len(patching_llm_calls),
                "total_cost": total_patch_cost,
                "total_input_tokens": total_patch_input_tokens,
                "total_output_tokens": total_patch_output_tokens,
                "total_cached_tokens": sum(call.get('cached_tokens', 0) for call in patching_llm_calls),
                "llm_calls": patching_llm_calls
            }
            
            # Calculate overall cost
            total_triage_cost = workflow_data.get("cost_analysis", {}).get("triage", {}).get("total_cost", 0)
            workflow_data["cost_analysis"]["total"] = {
                "total_cost": total_triage_cost + total_patch_cost,
                "total_input_tokens": workflow_data.get("cost_analysis", {}).get("triage", {}).get("total_input_tokens", 0) + total_patch_input_tokens,
                "total_output_tokens": workflow_data.get("cost_analysis", {}).get("triage", {}).get("total_output_tokens", 0) + total_patch_output_tokens,
                "total_llm_calls": workflow_data.get("cost_analysis", {}).get("triage", {}).get("total_llm_calls", 0) + len(patching_llm_calls)
            }
            
            # Check if we got a ConfirmedPatchResult (with actual patch) or just PatchResult
            if hasattr(patch_response, 'patch') and patch_response.success:
                print(f"  Patch generated: {len(patch_response.patch)} characters")
                print(f"  Build artifacts: {len(patch_response.build_artifacts) if patch_response.build_artifacts else 0}")
                print(f"  Tested POVs: {len(patch_response.tested_povs)}")
                
                # Save patch to ARVO-specific directory
                script_dir = Path(__file__).parent
                arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
                patch_file = arvo_dir / "generated_patch.diff"
                patch_file.write_text(patch_response.patch)
                print(f"Saved patch to: {patch_file}")
                
                # Update workflow data with patch results
                workflow_data["patch_result"] = {
                    "success": patch_response.success,
                    "patch": patch_response.patch,
                    "build_artifacts_count": len(patch_response.build_artifacts) if patch_response.build_artifacts else 0,
                    "tested_povs_count": len(patch_response.tested_povs)
                }
                if last_validation is not None:
                    workflow_data["patch_result"]["last_validation"] = last_validation.model_dump()
                
                # Add context capture data
                workflow_data["context_retrieval"] = context_capture
            else:
                print(f"  No patch generated")
                if hasattr(patch_response, 'failure_reason') and patch_response.failure_reason:
                    print(f"  Failure reason: {patch_response.failure_reason}")
                
                # Update workflow data with failure info
                workflow_data["patch_result"] = {
                    "success": patch_response.success,
                    "failure_reason": getattr(patch_response, 'failure_reason', 'Unknown failure')
                }
                if last_validation is not None:
                    workflow_data["patch_result"]["last_validation"] = last_validation.model_dump()
                    print(f"  Last validation status: {last_validation.status}")
                    print(f"  Last validation message: {last_validation.message}")
                
                # Add context capture data
                workflow_data["context_retrieval"] = context_capture
            
            # Re-save workflow data with patch results
            workflow_file.write_text(json.dumps(workflow_data, indent=2))
            print(f"Updated workflow data with patch results")
            
            # Print context retrieval summary
            print(f"\nContext Retrieval Summary:")
            total_calls = sum(len(calls) for calls in context_capture.values())
            print(f"  Total context retrieval calls: {total_calls}")
            for tool_name, calls in context_capture.items():
                if calls:
                    print(f"  {tool_name}: {len(calls)} calls")
                    for i, call in enumerate(calls):
                        print(f"    Call {i+1}: {call.get('args', [])[:2]}...")  # Show first 2 args
            
            # Save context retrieval data to ARVO-specific directory
            script_dir = Path(__file__).parent
            arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
            context_file = arvo_dir / "context_retrieval_data.json"
            context_file.write_text(json.dumps(context_capture, indent=2))
            print(f"Saved detailed context retrieval data to: {context_file}")
            
        else:
            print(f"Patching agent failed: {patch_result.err()}")
            
            # Get context capture data from the patching agent even on failure
            context_capture = patcher.get_context_capture() if hasattr(patcher, 'get_context_capture') else {}
            last_validation = patcher.get_last_validation() if hasattr(patcher, 'get_last_validation') else None
            
            # Get LLM cost data even on failure
            patching_llm_calls = patcher.get_llm_calls() if hasattr(patcher, 'get_llm_calls') else []
            total_patch_cost = sum(call.get('cost', 0) for call in patching_llm_calls)
            
            # Add patching cost to workflow data even on failure
            if "cost_analysis" not in workflow_data:
                workflow_data["cost_analysis"] = {}
            workflow_data["cost_analysis"]["patching"] = {
                "total_llm_calls": len(patching_llm_calls),
                "total_cost": total_patch_cost,
                "total_input_tokens": sum(call.get('input_tokens', 0) for call in patching_llm_calls),
                "total_output_tokens": sum(call.get('output_tokens', 0) for call in patching_llm_calls),
                "total_cached_tokens": sum(call.get('cached_tokens', 0) for call in patching_llm_calls),
                "llm_calls": patching_llm_calls
            }
            
            workflow_data["patch_result"] = {
                "success": False,
                "error": str(patch_result.err())
            }
            if last_validation is not None:
                workflow_data["patch_result"]["last_validation"] = last_validation.model_dump()
            # Add context capture data even on failure
            workflow_data["context_retrieval"] = context_capture
            workflow_file.write_text(json.dumps(workflow_data, indent=2))
            
    except Exception as e:
        print(f"Error running patching agent: {e}")
        
        # Get context capture data from the patching agent even on exception
        context_capture = patcher.get_context_capture() if hasattr(patcher, 'get_context_capture') else {}
        last_validation = patcher.get_last_validation() if hasattr(patcher, 'get_last_validation') else None
        
        # Get LLM cost data even on exception
        patching_llm_calls = patcher.get_llm_calls() if hasattr(patcher, 'get_llm_calls') else []
        total_patch_cost = sum(call.get('cost', 0) for call in patching_llm_calls)
        
        # Add patching cost to workflow data even on exception
        if "cost_analysis" not in workflow_data:
            workflow_data["cost_analysis"] = {}
        workflow_data["cost_analysis"]["patching"] = {
            "total_llm_calls": len(patching_llm_calls),
            "total_cost": total_patch_cost,
            "total_input_tokens": sum(call.get('input_tokens', 0) for call in patching_llm_calls),
            "total_output_tokens": sum(call.get('output_tokens', 0) for call in patching_llm_calls),
            "total_cached_tokens": sum(call.get('cached_tokens', 0) for call in patching_llm_calls),
            "llm_calls": patching_llm_calls
        }
        
        workflow_data["patch_result"] = {
            "success": False,
            "error": str(e)
        }
        if last_validation is not None:
            workflow_data["patch_result"]["last_validation"] = last_validation.model_dump()
        # Add context capture data even on exception
        workflow_data["context_retrieval"] = context_capture
        workflow_file.write_text(json.dumps(workflow_data, indent=2))
    
    return workflow_data


def print_summary(vuln_id, analyzed_vuln, decoded_pov, workflow_data):
    """Print final summary"""
    print("\n" + "="*60)
    print("COMPLETE CRS WORKFLOW FINISHED")
    print("="*60)
    print("Completed Full CRS Workflow:")
    print("  1. arvo run - PoC triggered crash (using authentic ARVO binary)")
    print("  2. Created POVRunData (like handle_pov_produce_result)")
    print("  3. decode_pov() - Decoded the POV")
    print("  4. CRSTriage.pov_triage() - Analyzed vulnerability with LLM")
    print("  5. productsdb.add_vuln() - Stored vulnerability in database")
    print("  6. Saved workflow data to ARVO directory")
    print("  7. CRSPatcher.patch_vulnerability() - Generated patches with LLM")
    print()
    print("Final Results:")
    print(f"  Vulnerability ID: {vuln_id} (stored in database)")
    print(f"  Vulnerable Function: {analyzed_vuln.function}")
    print(f"  Vulnerable File: {analyzed_vuln.file}")
    print(f"  Crash Dedup: {decoded_pov.dedup}")
    print(f"  Patch Generated: {'YES' if 'patch_result' in workflow_data and workflow_data['patch_result']['success'] else 'NO'}")
    if "patch_result" in workflow_data and workflow_data["patch_result"].get("last_validation"):
        lv = workflow_data["patch_result"]["last_validation"]
        print(f"  Last Validation Status: {lv.get('status')}")
        print(f"  Last Validation Message: {lv.get('message')}")
    print()
    
    # Print cost analysis summary
    if "cost_analysis" in workflow_data:
        cost_data = workflow_data["cost_analysis"]
        print("Cost Analysis:")
        if "total" in cost_data:
            print(f"  Total Cost: ${cost_data['total']['total_cost']:.4f}")
            print(f"  Total LLM Calls: {cost_data['total']['total_llm_calls']}")
            print(f"  Total Input Tokens: {cost_data['total']['total_input_tokens']}")
            print(f"  Total Output Tokens: {cost_data['total']['total_output_tokens']}")
        if "triage" in cost_data:
            print(f"  Triage Cost: ${cost_data['triage']['total_cost']:.4f} ({cost_data['triage']['total_llm_calls']} calls)")
        if "patching" in cost_data:
            print(f"  Patching Cost: ${cost_data['patching']['total_cost']:.4f} ({cost_data['patching']['total_llm_calls']} calls)")
        print()
    
    print("Output Files Saved:")
    print(f"  Configuration: arvo_{CONFIG['arvo_id']}/config.json")
    print(f"  Workflow Data: arvo_{CONFIG['arvo_id']}/workflow_data.json (includes cost analysis)")
    print(f"  Context Retrieval: arvo_{CONFIG['arvo_id']}/context_retrieval_data.json")
    if 'patch_result' in workflow_data and workflow_data['patch_result']['success']:
        print(f"  Generated Patch: arvo_{CONFIG['arvo_id']}/generated_patch.diff")
    print()
    print("Complete ARVO-to-CRS workflow executed successfully!")
    print("   From ARVO crash data to working patches using real CRS agents!")


async def test_poc(arvo_id):
    """Test the PoC against the vulnerable version - Following CRS workflow"""
    
    current_phase = "PHASE 1: SETTING UP PROJECT AND HARNESSES"
    try:
        # Phase 1: Setup project and harnesses
        task, harness_list, fuzzer_index = await setup_project_and_harnesses()
        if task is None:
            raise RuntimeError("Project/harness setup returned None")

        current_phase = "PHASE 2: BUILDING CRASH RESULT FROM METADATA"
        if not METADATA.get("sanitizer_report"):
            raise RuntimeError(
                "metadata.json entry is missing sanitizer_report; metadata-driven mode requires it."
            )
        crash_result, pov_python = await create_crash_result_from_metadata_report(task, METADATA)

        if crash_result is None:
            raise RuntimeError("CrashResult was None after ARVO crash processing")

        # Phase 3: Create POVRunData from crash
        current_phase = "PHASE 3: CREATING POVRunData FROM CRASH"
        pov_run_data = await create_pov_run_data(task, harness_list, fuzzer_index, crash_result, pov_python)

        # Phase 4: Decode POV
        current_phase = "PHASE 4: DECODING POV"
        decoded_pov, crs_instance = await decode_pov(task, harness_list, pov_run_data)

        # Phase 5: Triage vulnerability with LLM
        current_phase = "PHASE 5: TRIAGING POV WITH LLM"
        analyzed_vuln, triage_llm_calls = await triage_vulnerability(task, decoded_pov)
        if analyzed_vuln is None:
            raise RuntimeError("Triage returned no analyzed vulnerability")

        # Phase 6: Store vulnerability in database
        current_phase = "PHASE 6: STORING VULNERABILITY IN DATABASE"
        vuln_id = await store_vulnerability_in_database(crs_instance, task, analyzed_vuln)

        # Phase 7: Save workflow data
        current_phase = "PHASE 7: SAVING WORKFLOW DATA"
        workflow_data, workflow_file = save_workflow_data(vuln_id, crash_result, pov_run_data, decoded_pov, analyzed_vuln, arvo_id, triage_llm_calls)

        # Phase 8: Run patching agent
        current_phase = "PHASE 8: RUNNING PATCHING AGENT"
        workflow_data = await run_patching_agent(task, analyzed_vuln, decoded_pov, vuln_id, workflow_data, workflow_file, arvo_id)

        # Print summary
        current_phase = "FINAL SUMMARY"
        print_summary(vuln_id, analyzed_vuln, decoded_pov, workflow_data)

        return crash_result, pov_run_data, decoded_pov, analyzed_vuln, vuln_id
    except Exception as e:
        save_failure_data(arvo_id=arvo_id, phase=current_phase, exc=e)
        raise

if __name__ == "__main__":
    # Get ARVO ID from command line arguments (already loaded in CONFIG)
    arvo_id = CONFIG['arvo_id']
    try:
        asyncio.run(test_poc(arvo_id))
    except Exception as e:
        # test_poc already persisted a failure record; this is the final fallback
        print(f"\n{'='*60}")
        print(f"FATAL ERROR: Uncaught exception")
        print(f"{'='*60}")
        print(f"Exception: {e}")
        traceback.print_exc()
        print(f"{'='*60}")
        sys.exit(1)
