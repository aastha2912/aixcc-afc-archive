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
OSS_FUZZ_DOWNLOAD_BASE_URL = "https://oss-fuzz.com/download"
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

    # Parse comments for fuzzer target and reproducer testcase URL
    for comment_entry in metadata.get("report", {}).get("comments", []):
        content = comment_entry.get("content", "")
        
        # Extract Fuzz Target
        fuzzer_match = re.search(r"Fuzz Target: (\S+)", content)
        if fuzzer_match:
            project_info["fuzzer_name"] = fuzzer_match.group(1)
        
        # Extract Reproducer Testcase URL
        poc_match = re.search(r"Reproducer Testcase: (https://oss-fuzz.com/download\?testcase_id=\d+)", content)
        if poc_match:
            project_info["poc_download_url"] = poc_match.group(1)
            break # Stop after finding the first POC URL

    return project_info

def download_testcase_file(poc_url: str, project_dir: str) -> tuple[bool, str]:
    """Download testcase file and save it to the project directory with testcase_ prefix"""
    if not poc_url:
        print("No POC download URL found")
        return False, None
    
    # Extract original filename from URL (testcase_id) and add testcase_ prefix
    testcase_match = re.search(r'testcase_id=(\d+)', poc_url)
    if testcase_match:
        original_filename = f"testcase_{testcase_match.group(1)}.bin"
    else:
        original_filename = "testcase.bin"
    
    # Create project directory if it doesn't exist (relative to script location)
    script_dir = Path(__file__).parent
    project_path = script_dir / "../.." / project_dir
    project_path = project_path.resolve()  # Convert to absolute path
    project_path.mkdir(parents=True, exist_ok=True)
    
    # Download the POC file with original filename
    poc_file_path = project_path / original_filename
    
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

def get_project_files_list(project_name: str) -> list:
    """Get list of files in the OSS-Fuzz project directory"""
    # Common OSS-Fuzz project files
    common_files = [
        "Dockerfile",
        "build.sh", 
        "project.yaml",
        f"{project_name}_fuzzer.cc",
        f"{project_name}_fuzzer.cpp",
        f"{project_name}_fuzzer.c",
        "fuzzer.cc",
        "fuzzer.cpp", 
        "fuzzer.c"
    ]
    
    return common_files

def download_project_file(project_name: str, filename: str, target_dir: Path) -> bool:
    """Download a single project file"""
    url = f"{OSS_FUZZ_BASE_URL}/{project_name}/{filename}"
    
    print(f"Downloading: {filename}")
    
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
            
            # Save the file
            file_path = target_dir / filename
            with open(file_path, 'wb') as f:
                f.write(data)
            
            print(f"Downloaded: {file_path}")
            return True
            
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"File not found: {filename} (404)")
            return False
        else:
            print(f"Error downloading {filename}: {e}")
            return False
    except urllib.error.URLError as e:
        print(f"Error downloading {filename}: {e}")
        return False

def download_oss_fuzz_project(project_name: str, target_dir: str) -> bool:
    """Download all OSS-Fuzz project files"""
    print(f"\nDownloading OSS-Fuzz project files for: {project_name}")
    print("-" * 50)
    
    # Create target directory (relative to script location)
    script_dir = Path(__file__).parent
    project_path = script_dir / "../.." / target_dir
    project_path = project_path.resolve()  # Convert to absolute path
    project_path.mkdir(parents=True, exist_ok=True)
    
    # Get list of files to download
    files_to_download = get_project_files_list(project_name)
    
    downloaded_count = 0
    total_files = len(files_to_download)
    
    for filename in files_to_download:
        success = download_project_file(project_name, filename, project_path)
        if success:
            downloaded_count += 1
        print()  # Add spacing between files
    
    print(f"Download Summary: {downloaded_count}/{total_files} files downloaded")
    
    return downloaded_count > 0

def modify_dockerfile_for_vulnerable_version(project_info: dict, project_dir: str) -> bool:
    """Modify the Dockerfile to clone the vulnerable version instead of latest"""
    if not project_info.get('repo_addr') or not project_info.get('fix_commit'):
        print("No repository address or fix commit found in metadata")
        return False
    
    repo_url = project_info['repo_addr']
    fix_commit = project_info['fix_commit']
    
    print(f"\nModifying Dockerfile for vulnerable version...")
    print(f"Repository: {repo_url}")
    print(f"Fix commit: {fix_commit}")
    print("-" * 50)
    
    # Create project directory (relative to script location)
    script_dir = Path(__file__).parent
    project_path = script_dir / "../.." / project_dir
    project_path = project_path.resolve()
    
    dockerfile_path = project_path / "Dockerfile"
    
    if not dockerfile_path.exists():
        print(f"Dockerfile not found: {dockerfile_path}")
        return False
    
    try:
        # Read the current Dockerfile
        with open(dockerfile_path, 'r') as f:
            dockerfile_content = f.read()
        
        # Find the git clone line and modify it
        # Original: RUN git clone --depth 1 https://github.com/libraw/libraw
        # Modified: RUN git clone https://github.com/libraw/libraw && cd libraw && git checkout <vulnerable_commit>
        
        # Get the parent commit (vulnerable version) - we'll need to do this in the Dockerfile
        # For now, let's modify the git clone line to checkout the vulnerable commit
        
        # Replace the git clone line
        old_clone_line = "RUN git clone --depth 1 https://github.com/libraw/libraw"
        new_clone_line = f"""RUN git clone https://github.com/libraw/libraw && \\
    cd libraw && \\
    git checkout {fix_commit}^ && \\
    cd .."""
        
        if old_clone_line in dockerfile_content:
            dockerfile_content = dockerfile_content.replace(old_clone_line, new_clone_line)
            
            # Write the modified Dockerfile
            with open(dockerfile_path, 'w') as f:
                f.write(dockerfile_content)
            
            print(f"Modified Dockerfile to checkout vulnerable version")
            print(f"Vulnerable commit: {fix_commit}^ (parent of fix commit)")
            
            # Create a backup of the original
            backup_path = project_path / "Dockerfile.original"
            with open(backup_path, 'w') as f:
                f.write(dockerfile_content.replace(new_clone_line, old_clone_line))
            print(f"Original Dockerfile backed up to: {backup_path}")
            
            return True
        else:
            print(f"Could not find expected git clone line in Dockerfile")
            return False
            
    except Exception as e:
        print(f"Error modifying Dockerfile: {e}")
        return False

def generate_config_info(project_info: dict, testcase_filename: str, arvo_id: str) -> str:
    """Generate configuration information for the main script"""
    if not project_info:
        return None

    config_info = f"""
# Generated configuration for ARVO ID: {arvo_id}
# Project: {project_info.get('project_name', 'N/A')}
# Fuzzer: {project_info.get('fuzzer_name', 'N/A')}
# Sanitizer: {project_info.get('sanitizer', 'N/A')}
# Crash Type: {project_info.get('crash_type', 'N/A')}

# Update these parameters in arvo_to_crs_integration.py:
PROJECT_DIR = "projects/{project_info.get('project_name', 'N/A')}"
POC_FILE = "{testcase_filename}"
FUZZER_NAME = "{project_info.get('fuzzer_name', 'N/A')}"

# Repository and commit info:
# Fix commit: {project_info.get('fix_commit', 'N/A')}
# Vulnerable version: Check projects/{project_info.get('project_name', 'N/A')}/src/VULNERABLE_VERSION_INFO.md
# Repo: {project_info.get('repo_addr', 'N/A')}

# Directory structure:
# projects/{project_info.get('project_name', 'N/A')}/
# ├── Dockerfile             # OSS-Fuzz build configuration (modified to clone vulnerable version)
# ├── Dockerfile.original    # Backup of original Dockerfile
# ├── build.sh               # OSS-Fuzz build script
# ├── project.yaml           # OSS-Fuzz project config
# ├── {project_info.get('fuzzer_name', 'N/A')}.cc  # OSS-Fuzz fuzzer harness
# └── {testcase_filename}    # ARVO testcase file
#
# Note: When Docker builds, it will clone the vulnerable version (parent of fix commit)
"""
    return config_info

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
    
    # Step 2: Download testcase file
    print("\nStep 2: Downloading testcase file...")
    if project_info["poc_download_url"]:
        project_dir = f"projects/{project_info['project_name']}"
        success, testcase_filename = download_testcase_file(
            project_info["poc_download_url"], 
            project_dir
        )
        
        if not success:
            print("Failed to download testcase file")
            sys.exit(1)
    else:
        print("No POC download URL found in metadata")
        sys.exit(1)
    
    # Step 3: Download OSS-Fuzz project files
    print("\nStep 3: Downloading OSS-Fuzz project files...")
    success = download_oss_fuzz_project(project_info['project_name'], project_dir)
    
    if not success:
        print("Failed to download any project files")
        sys.exit(1)
    
    # Step 4: Modify Dockerfile for vulnerable version
    print("\nStep 4: Modifying Dockerfile for vulnerable version...")
    success = modify_dockerfile_for_vulnerable_version(project_info, project_dir)
    
    if not success:
        print("Failed to modify Dockerfile")
        sys.exit(1)
    
    # Step 5: Generate configuration info
    print("\nStep 5: Generating configuration...")
    config_info = generate_config_info(project_info, testcase_filename, arvo_id)
    
    print("\nConfiguration for arvo_to_crs_integration.py:")
    print("-" * 50)
    print(config_info)
    
    # Save configuration to a JSON file for the integration script
    script_dir = Path(__file__).parent
    arvo_dir = script_dir / ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)
    arvo_dir.mkdir(exist_ok=True)
    
    config_data = {
        "arvo_id": arvo_id,
        "project_name": project_info.get('project_name', 'N/A'),
        "fuzzer_name": project_info.get('fuzzer_name', 'N/A'),
        "sanitizer": project_info.get('sanitizer', 'N/A'),
        "crash_type": project_info.get('crash_type', 'N/A'),
        "fix_commit": project_info.get('fix_commit', 'N/A'),
        "repo_addr": project_info.get('repo_addr', 'N/A'),
        "project_dir": f"projects/{project_info.get('project_name', 'N/A')}",
        "poc_file": testcase_filename
    }
    
    config_file = arvo_dir / ARVO_CONFIG_FILE_NAME
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print(f"\nConfiguration saved to: {config_file}")
    print(f"ARVO directory created: {arvo_dir}")
    
    print("\n" + "="*60)
    print("ARVO PROJECT SETUP COMPLETE")
    print("="*60)
    print(f"Project directory: {project_dir}")
    print(f"Testcase file: {testcase_filename}")
    print(f"Configuration file: {ARVO_CONFIG_DIR_NAME.format(arvo_id=arvo_id)}/{ARVO_CONFIG_FILE_NAME}")
    print("\nTo run the integration script:")
    print(f"python3 arvo_to_crs_integration.py {arvo_id}")

if __name__ == "__main__":
    main()
