#!/usr/bin/env python3
"""
Complete ARVO project setup: Fetch metadata, download testcase, and download OSS-Fuzz project files
"""
import os
import sys
import json
import urllib.request
import urllib.error
from pathlib import Path
import re

# =============================================================================
# CONFIGURATION
# =============================================================================

ARVO_META_BASE_URL = "https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta"
OSS_FUZZ_BASE_URL = "https://raw.githubusercontent.com/google/oss-fuzz/master/projects"

# Directory structure
ARVO_CONFIG_DIR_NAME = "arvo_{arvo_id}"  # Directory name for ARVO configurations
ARVO_CONFIG_FILE_NAME = "config.json"    # Configuration file name

# =============================================================================
# FUNCTIONS
# =============================================================================

def fetch_arvo_metadata(arvo_id: str) -> dict:
    """Fetch ARVO metadata for the given ID"""
    url = f"{ARVO_META_BASE_URL}/{arvo_id}.json"
    
    print(f"Fetching ARVO metadata from: {url}")
    
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read().decode('utf-8')
            return json.loads(data)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"Error fetching metadata: {e}")
        return None

def extract_project_info(metadata: dict) -> dict:
    """Extract project information from ARVO metadata"""
    if not metadata:
        return None

    project_info = {
        "project_name": metadata.get("project"),
        "fuzzer_name": None,
        "sanitizer": metadata.get("sanitizer"),
        "crash_type": metadata.get("crash_type"),
        "fix_commit": metadata.get("fix_commit"),
        "repo_addr": metadata.get("repo_addr"),
        "poc_download_url": None,
    }

    # Parse comments for OSS-Fuzz project name, fuzzer target, and reproducer testcase URL
    for comment_entry in metadata.get("report", {}).get("comments", []):
        content = comment_entry.get("content", "")
        
        # Extract actual OSS-Fuzz project name from comment text
        # Example: metadata has "project": "binutils-gdb" (git repo)
        #          but comment says "Project: binutils" (OSS-Fuzz project name)
        # We need the OSS-Fuzz project name for correct project.yaml download
        project_match = re.search(r"^Project:\s*(\S+)", content, re.MULTILINE)
        if project_match:
            project_info["project_name"] = project_match.group(1)
        
        # Extract Fuzz target binary (multiple patterns to handle variations)
        # Pattern 1: "Fuzz target binary: fuzzshark_ip"
        fuzzer_match = re.search(r"Fuzz target binary:\s*(\S+)", content, re.IGNORECASE)
        if fuzzer_match:
            project_info["fuzzer_name"] = fuzzer_match.group(1)
        # Pattern 2: "Fuzz Target: libraw_fuzzer" (older format)
        if not project_info["fuzzer_name"]:
            fuzzer_match = re.search(r"Fuzz Target:\s*(\S+)", content, re.IGNORECASE)
            if fuzzer_match:
                project_info["fuzzer_name"] = fuzzer_match.group(1)
        
        # Extract Reproducer Testcase URL
        poc_match = re.search(r"Reproducer Testcase:\s*(https://oss-fuzz.com/download\?testcase_id=\d+)", content)
        if poc_match:
            project_info["poc_download_url"] = poc_match.group(1)
        
        # Break after finding POC and project name (everything we need from first comment)
        if project_info["poc_download_url"] and project_match:
            break

    return project_info

def download_testcase_file(poc_url: str, arvo_dir: Path) -> tuple[bool, str]:
    """Download testcase file and save it to the ARVO config directory"""
    if not poc_url:
        print("No POC download URL found")
        return False, None
    
    # Extract original filename from URL (testcase_id) and add testcase_ prefix
    testcase_match = re.search(r'testcase_id=(\d+)', poc_url)
    if testcase_match:
        original_filename = f"testcase_{testcase_match.group(1)}.bin"
    else:
        original_filename = "testcase.bin"
    
    # Download the POC file to ARVO directory
    poc_file_path = arvo_dir / original_filename
    
    print(f"Downloading testcase from: {poc_url}")
    print(f"Saving to: {poc_file_path}")
    
    try:
        with urllib.request.urlopen(poc_url) as response:
            data = response.read()
            
            with open(poc_file_path, 'wb') as f:
                f.write(data)
            
            print(f"Testcase file downloaded successfully: {poc_file_path}")
            return True, original_filename
            
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"Error downloading testcase file: {e}")
        return False, None



# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python setup_arvo_project.py <ARVO_ID>")
        print("Example: python setup_arvo_project.py 65027")
        sys.exit(1)

    arvo_id = sys.argv[1]
    print("\n" + "="*60)
    print(f"COMPLETE ARVO PROJECT SETUP FOR ID: {arvo_id}")
    print("="*60)

    # Step 1: Fetch ARVO metadata
    print("\nStep 1: Fetching ARVO metadata...")
    metadata = fetch_arvo_metadata(arvo_id)
    if not metadata:
        sys.exit(1)

    project_info = extract_project_info(metadata)
    if not project_info:
        print("Failed to extract project information.")
        sys.exit(1)

    print("\nExtracted Project Information:")
    print("-" * 40)
    for key, value in project_info.items():
        print(f"{key}: {value}")
    
    # Step 2: Create ARVO directory and download testcase
    print("\nStep 2: Setting up ARVO directory and downloading testcase...")
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    arvo_dir.mkdir(exist_ok=True)
    print(f"Created directory: {arvo_dir}")
    
    if project_info["poc_download_url"]:
        success, testcase_filename = download_testcase_file(
            project_info["poc_download_url"], 
            arvo_dir
        )
        
        if not success:
            print("Failed to download testcase file")
            sys.exit(1)
    else:
        print("No POC download URL found in metadata")
        sys.exit(1)
    
    # Step 3: Create project directory and download project.yaml
    print("\nStep 3: Setting up project configuration...")
    script_dir = Path(__file__).parent
    project_dir_path = script_dir / "../.." / f"projects/{project_info['project_name']}"
    project_dir_path = project_dir_path.resolve()
    project_dir_path.mkdir(parents=True, exist_ok=True)
    
    # Download project.yaml from OSS-Fuzz
    print("Downloading project.yaml from OSS-Fuzz...")
    
    # Download the real project.yaml from OSS-Fuzz
    project_yaml_path = project_dir_path / "project.yaml"
    project_yaml_url = f"{OSS_FUZZ_BASE_URL}/{project_info['project_name']}/project.yaml"
    
    print(f"Downloading from: {project_yaml_url}")
    try:
        with urllib.request.urlopen(project_yaml_url) as response:
            project_yaml_content = response.read()
            
            with open(project_yaml_path, 'wb') as f:
                f.write(project_yaml_content)
            
            print(f"✓ Downloaded: {project_yaml_path}")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"Warning: Could not download project.yaml: {e}")
        print("Creating fallback project.yaml...")
        # Fallback to minimal version if download fails
        repo_url = project_info.get('repo_addr', 'https://github.com/google/oss-fuzz')
        project_yaml_content = f"""homepage: "{repo_url}"
language: c++
main_repo: "{repo_url}"
primary_contact: "arvo@test.com"
sanitizers:
  - address
  - undefined
"""
        with open(project_yaml_path, 'w') as f:
            f.write(project_yaml_content)
        print(f"Created fallback: {project_yaml_path}")
    
    # Step 4: Save configuration
    print("\nStep 4: Saving configuration...")
    
    config_data = {
        "arvo_id": arvo_id,
        "project_name": project_info.get('project_name', 'N/A'),
        "fuzzer_name": project_info.get('fuzzer_name', 'N/A'),
        "sanitizer": project_info.get('sanitizer', 'N/A'),
        "crash_type": project_info.get('crash_type', 'N/A'),
        "fix_commit": project_info.get('fix_commit', 'N/A'),
        "repo_addr": project_info.get('repo_addr', 'N/A'),
        "project_dir": f"projects/{project_info.get('project_name', 'N/A')}",
        "poc_file": f"crs/arvo-patching-agent/arvo_{arvo_id}/{testcase_filename}",  # Relative path from workspace root
        # Prebuilt vulnerable image (local or remote). Default matches the server's naming scheme.
        "arvo_image_name": f"vulpatch:{arvo_id}-vul",
        "use_prebuilt_image": True  # Set to False to build from source instead
    }
    
    config_file = arvo_dir / ARVO_CONFIG_FILE_NAME
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print(f"\nConfiguration saved to: {config_file}")
    print(f"ARVO directory created: {arvo_dir}")
    
    print("\n" + "="*60)
    print("ARVO PROJECT SETUP COMPLETE")
    print("="*60)
    print(f"ARVO ID: {arvo_id}")
    print(f"Project: {project_info['project_name']}")
    print(f"Fuzzer: {project_info['fuzzer_name']}")
    print(f"Testcase: {arvo_dir / testcase_filename}")
    print(f"Docker Image: {config_data['arvo_image_name']}")
    print(f"Config: {config_file}")
    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("="*60)
    print(f"Run inside Docker container:")
    print(f"  docker-compose exec crs-main bash -c \"source /crs/.venv/bin/activate && python3 crs/arvo-patching-agent/arvo_to_crs_integration.py {arvo_id}\"")
    print("\nThe script will:")
    print(f"  1. Pull prebuilt image: {config_data['arvo_image_name']}")
    print("  2. Extract /src (source code) - NO Dockerfile build needed")
    print("  3. Extract /out (binaries) - NO compilation needed")
    print("  4. Test PoC and generate patches")
    print("\nNote: Everything comes from ARVO prebuilt image - no building required!")

if __name__ == "__main__":
    main()
