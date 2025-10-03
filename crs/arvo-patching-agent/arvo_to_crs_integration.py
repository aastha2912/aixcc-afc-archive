#!/usr/bin/env python3
"""
Test PoC against different projects - Following actual CRS workflow
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

async def setup_project_and_harnesses():
    """Phase 1: Setup project and find harnesses"""
    print("\n" + "="*60)
    print("PHASE 1: SETTING UP PROJECT AND HARNESSES")
    print("="*60)
    print(f"Configuration:")
    print(f"  Project: {PROJECT_DIR}")
    print(f"  POC File: {POC_FILE}")
    print(f"  Fuzzer: {FUZZER_NAME}")
    print("="*60)
    
    # Load project
    project = await TestProject.from_dir(PROJECT_DIR)
    task = await project.task()
    
    # Build the project first
    print("Building project...")
    build_result = await task.project.build_all()
    if build_result.is_err():
        print(f"Build failed: {build_result.err()}")
        return None, None, None
    print("Project built successfully")
    
    # Initialize harness info
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
    
    # Find the specified fuzzer harness
    fuzzer_index = None
    for i, name in enumerate(harness_names):
        if name == FUZZER_NAME:
            fuzzer_index = i
            break
    
    if fuzzer_index is None:
        print(f"Fuzzer harness '{FUZZER_NAME}' not found!")
        print(f"Available harnesses: {harness_names}")
        return None, None, None
    
    print(f"Using harness: {harness_list[fuzzer_index].name} (index {fuzzer_index})")
    
    return task, harness_list, fuzzer_index


def prepare_poc_data():
    """Prepare PoC data for testing"""
    # Check if you have a real PoC file
    poc_file = Path(PROJECT_DIR) / POC_FILE
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
    print("  1. test_pov() - PoC triggered crash")
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
    
    # Phase 2: Test PoC and get crash result
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
