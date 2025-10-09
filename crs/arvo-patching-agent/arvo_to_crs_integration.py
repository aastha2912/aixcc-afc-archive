#!/usr/bin/env python3
"""
Test PoC against different projects - Following actual CRS workflow

This script integrates ARVO vulnerability data with the CRS patching system.
It can use prebuilt ARVO Docker images to avoid rebuilding projects from source.

ARVO images (n132/arvo:{id}-vul) contain:
  - Pre-compiled vulnerable version in /out
  - Source code in /src
  - 'arvo compile' command to rebuild after patching
  - 'arvo run' command to test with the PoC

Configuration (in arvo_<id>/config.json):
  - use_prebuilt_image: Set to true to use prebuilt ARVO images (default)
  - arvo_image_name: Docker image name (format: n132/arvo:{id}-vul)
"""
import asyncio
import sys
import json
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path.cwd()))

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

def get_config_from_args():
    """Get configuration from command line arguments"""
    if len(sys.argv) < 2:
        print("Usage: python3 arvo_to_crs_integration.py <ARVO_ID>")
        print("Example: python3 arvo_to_crs_integration.py 65027")
        sys.exit(1)
    
    arvo_id = sys.argv[1]
    config = load_arvo_config(arvo_id)
    
    print(f"\nLoaded configuration for ARVO ID: {arvo_id}")
    print(f"Project: {config['project_name']}")
    print(f"Fuzzer: {config['fuzzer_name']}")
    print(f"POC File: {config['poc_file']}")
    print("="*60)
    
    return config

# Load configuration from command line arguments
CONFIG = get_config_from_args()

# Extract configuration parameters
PROJECT_DIR = CONFIG['project_dir']
POC_FILE = CONFIG['poc_file']
FUZZER_NAME = CONFIG['fuzzer_name']

# =============================================================================
# END CONFIGURATION LOADING
# =============================================================================

def pull_arvo_image_if_needed(arvo_image_name: str) -> bool:
    """
    Pull ARVO Docker image if it doesn't exist locally.
    
    Returns:
        True if image is available (existed or pulled successfully)
        False if pull failed
    """
    import subprocess
    
    print("Checking for ARVO image...")
    proc_check = subprocess.run(
        ["docker", "image", "inspect", arvo_image_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    if proc_check.returncode != 0:
        # Image does not exist locally, pull it
        print(f"Pulling ARVO image: {arvo_image_name}")
        proc_pull = subprocess.run(
            ["docker", "pull", arvo_image_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if proc_pull.returncode != 0:
            print(f"Failed to pull ARVO image: {proc_pull.stderr.decode()}")
            return False
        else:
            print(f"Successfully pulled ARVO image")
            return True
    else:
        print(f"ARVO image already exists locally")
        return True


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
        async with docker.run(arvo_image_name, timeout=60, group=docker.DockerGroup.Misc) as run:
            # Run tar inside ARVO container to package /src
            proc = await run.exec(
                "tar", "cf", "-", "--transform", r"s/^\.\///", "-C", "/src", ".",
                stdout=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            if proc.returncode != 0:
                print(f"Failed to extract /src from ARVO image")
                return False
            
            # Save to cache location where project.py expects it
            # When project.py checks "if src.tar exists", it will find this and skip Dockerfile build
            with open(src_tar_path, "wb") as f:
                f.write(stdout)
            print(f"Extracted source code from ARVO image")
            print(f"CRS will detect src.tar and skip Dockerfile build entirely")
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
                async with docker.run(arvo_image_name, timeout=60, group=docker.DockerGroup.Misc) as run:
                    # Extract /out from the container (contains prebuilt fuzzers)
                    proc = await run.exec(
                        "tar", "cf", "-", "--transform", r"s/^\.\///", "-C", "/out", ".",
                        stdout=asyncio.subprocess.PIPE,
                    )
                    
                    # Write tar to file
                    stdout, _ = await proc.communicate()
                    
                    if proc.returncode != 0:
                        print(f"Failed to extract build artifacts for {build_config.SANITIZER}")
                        return False
                    
                    # Write to the expected build tar path so build() will use the cache
                    # When CRS calls build(), it will find this and skip compilation
                    with open(build_tar_path, "wb") as f:
                        f.write(stdout)
                    print(f"Extracted prebuilt binaries for {build_config.SANITIZER}")
            
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
    
    if use_prebuilt_image and arvo_image_name:
        print(f"  Using prebuilt ARVO image: {arvo_image_name}")
    else:
        print(f"  Will build project from source")
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
            print("Will build from source using Dockerfile...")
            use_prebuilt_image = False
        
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
                    use_prebuilt_image = False
                    print("Will build from source using Dockerfile...")
                    
            except Exception as e:
                print(f"Error during ARVO setup: {e}")
                import traceback
                traceback.print_exc()
                print("Will build from source using Dockerfile...")
                use_prebuilt_image = False
    
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
    
    # =========================================================================
    # Step 6: Extract prebuilt binaries from ARVO /out
    # =========================================================================
    # Extract fuzzers for each sanitizer (address, undefined, etc.)
    if use_prebuilt_image and arvo_image_name and prebuilt_setup_done:
        if not await extract_arvo_binaries(task, arvo_image_name):
            print("Falling back to building from source...")
            use_prebuilt_image = False
    
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
    fuzzer_index = find_fuzzer_index(harness_list, FUZZER_NAME)
    
    if fuzzer_index is None:
        print(f"Fuzzer harness '{FUZZER_NAME}' not found!")
        print(f"Available harnesses: {harness_names}")
        return None, None, None
    
    print(f"Using harness: {harness_list[fuzzer_index].name} (index {fuzzer_index})")
    
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


async def run_arvo_and_capture_crash(arvo_image_name: str, testcase_path: Path, fuzzer_name: str) -> str:
    """
    Run ARVO to test the PoC and capture the crash output.
    
    This uses ARVO's prebuilt vulnerable binary, avoiding the rebuild problem.
    
    Args:
        arvo_image_name: ARVO Docker image (e.g., "n132/arvo:65027-vul")
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
    
    # Parse ARVO output to extract crash information
    lines = arvo_crash_output.split('\n')
    
    # Extract stack trace (lines starting with #)
    stack_lines = []
    dedup_token = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            stack_lines.append(line.strip())
        elif 'DEDUP_TOKEN:' in line:
            dedup_token = line.split('DEDUP_TOKEN:', 1)[1].strip()
    
    if not stack_lines:
        print("ERROR: No stack trace found in ARVO output")
        return None, None
    
    stack = '\n'.join(stack_lines)
    
    # Use the dedup from ARVO or generate from stack
    if not dedup_token:
        from hashlib import sha256
        dedup_token = sha256(stack.encode()).hexdigest()
    
    # Get build config (use address sanitizer as default for ARVO)
    build_config = task.project.info.default_build_config
    
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
    print(f"  Stack frames: {len(stack_lines)}")
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
        return None
    
    analyzed_vuln = analyzed_vuln_result.unwrap()
    print(f"Vulnerability Analysis Complete:")
    print(f"  Function: {analyzed_vuln.function}")
    print(f"  File: {analyzed_vuln.file}")
    print(f"  Description: {analyzed_vuln.description[:200]}...")
    print(f"  Conditions: {len(analyzed_vuln.conditions)} conditions")
    
    return analyzed_vuln


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


def save_workflow_data(vuln_id, crash_result, pov_run_data, decoded_pov, analyzed_vuln, arvo_id):
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
        }
    }
    
    # Save to ARVO-specific directory
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    workflow_file = arvo_dir / "workflow_data.json"
    workflow_file.write_text(json.dumps(workflow_data, indent=2))
    print(f"Saved workflow data to: {workflow_file}")
    
    return workflow_data, workflow_file


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
            
            workflow_data["patch_result"] = {
                "success": False,
                "error": str(patch_result.err())
            }
            # Add context capture data even on failure
            workflow_data["context_retrieval"] = context_capture
            workflow_file.write_text(json.dumps(workflow_data, indent=2))
            
    except Exception as e:
        print(f"Error running patching agent: {e}")
        
        # Get context capture data from the patching agent even on exception
        context_capture = patcher.get_context_capture() if hasattr(patcher, 'get_context_capture') else {}
        
        workflow_data["patch_result"] = {
            "success": False,
            "error": str(e)
        }
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
    print()
    print("Output Files Saved:")
    print(f"  Configuration: arvo_{CONFIG['arvo_id']}/config.json")
    print(f"  Workflow Data: arvo_{CONFIG['arvo_id']}/workflow_data.json")
    print(f"  Context Retrieval: arvo_{CONFIG['arvo_id']}/context_retrieval_data.json")
    if 'patch_result' in workflow_data and workflow_data['patch_result']['success']:
        print(f"  Generated Patch: arvo_{CONFIG['arvo_id']}/generated_patch.diff")
    print()
    print("Complete ARVO-to-CRS workflow executed successfully!")
    print("   From ARVO crash data to working patches using real CRS agents!")


async def test_poc(arvo_id):
    """Test the PoC against the vulnerable version - Following CRS workflow"""
    
    # Phase 1: Setup project and harnesses
    task, harness_list, fuzzer_index = await setup_project_and_harnesses()
    if task is None:
        return None
    
    # Phase 2: Get crash from ARVO (not from CRS rebuild)
    # This uses ARVO's prebuilt vulnerable binary to get the authentic crash
    use_arvo_crash = CONFIG.get('use_prebuilt_image', True)
    
    if use_arvo_crash and CONFIG.get('arvo_image_name'):
        print("\n" + "="*60)
        print("Using ARVO run output (skipping CRS test_pov)")
        print("="*60)
        
        # Run ARVO to get authentic crash
        arvo_crash_output = await run_arvo_and_capture_crash(
            arvo_image_name=CONFIG['arvo_image_name'],
            testcase_path=Path(POC_FILE),
            fuzzer_name=FUZZER_NAME
        )
        
        if not arvo_crash_output:
            print("Failed to get ARVO crash output, falling back to CRS test")
            crash_result, pov_python = await test_poc_crash(task, harness_list, fuzzer_index)
        else:
            # Create CrashResult from ARVO output
            crash_result, pov_python = await create_crash_result_from_arvo(
                task, harness_list, fuzzer_index, arvo_crash_output
            )
    else:
        print("\n" + "="*60)
        print("Using CRS test_pov (may rebuild binaries)")
        print("="*60)
        crash_result, pov_python = await test_poc_crash(task, harness_list, fuzzer_index)
    
    if crash_result is None:
        return None
    
    # Phase 3: Create POVRunData from crash
    pov_run_data = await create_pov_run_data(task, harness_list, fuzzer_index, crash_result, pov_python)
    
    # Phase 4: Decode POV
    decoded_pov, crs_instance = await decode_pov(task, harness_list, pov_run_data)
    
    # Phase 5: Triage vulnerability with LLM
    analyzed_vuln = await triage_vulnerability(task, decoded_pov)
    if analyzed_vuln is None:
        return None
    
    # Phase 6: Store vulnerability in database
    vuln_id = await store_vulnerability_in_database(crs_instance, task, analyzed_vuln)
    
    # Phase 7: Save workflow data
    workflow_data, workflow_file = save_workflow_data(vuln_id, crash_result, pov_run_data, decoded_pov, analyzed_vuln, arvo_id)
    
    # Phase 8: Run patching agent
    workflow_data = await run_patching_agent(task, analyzed_vuln, decoded_pov, vuln_id, workflow_data, workflow_file, arvo_id)
    
    # Print summary
    print_summary(vuln_id, analyzed_vuln, decoded_pov, workflow_data)
    
    return crash_result, pov_run_data, decoded_pov, analyzed_vuln, vuln_id

if __name__ == "__main__":
    # Get ARVO ID from command line arguments (already loaded in CONFIG)
    arvo_id = CONFIG['arvo_id']
    asyncio.run(test_poc(arvo_id))
