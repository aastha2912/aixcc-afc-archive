#!/usr/bin/env python3
"""
(aastham) Generic script to create local task JSON files for any project.
This bypasses the Docker build issues and creates working task files.
"""

import argparse
import json
import datetime
import hashlib
import tarfile
import io
from uuid import uuid4
from pathlib import Path

def compute_sha256(filepath):
    """Compute SHA256 hash of a file"""
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def create_dummy_repo_tar(project_name: str, output_path: Path):
    """Create a minimal repo tar file for testing"""
    with tarfile.open(output_path, "w:gz") as tar:
        # Add a dummy project file
        dummy_content = f"# Dummy {project_name} project file\n# This is a placeholder for testing\n".encode()
        tarinfo = tarfile.TarInfo(name=f"{project_name}/README.md")
        tarinfo.size = len(dummy_content)
        tar.addfile(tarinfo, io.BytesIO(dummy_content))
        
        # Add a dummy source file
        source_content = f"#include <stdio.h>\nint main() {{ printf(\"Hello from {project_name}\"); return 0; }}\n".encode()
        tarinfo = tarfile.TarInfo(name=f"{project_name}/main.c")
        tarinfo.size = len(source_content)
        tar.addfile(tarinfo, io.BytesIO(source_content))

def create_task_json(project_name: str, projects_tar_path: Path, repo_tar_path: Path, output_path: Path):
    """Create a task JSON file with local file URLs"""
    
    # Get SHA256 hashes
    projects_sha256 = compute_sha256(projects_tar_path)
    repo_sha256 = compute_sha256(repo_tar_path)
    
    # Create task JSON
    task_id = uuid4()
    message_id = uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)
    
    task_data = {
        "message_id": str(message_id),
        "message_time": int(now.timestamp() * 1000),
        "tasks": [
            {
                "deadline": int((now + datetime.timedelta(days=365)).timestamp() * 1000),
                "focus": project_name,
                "harnesses_included": True,
                "metadata": {
                    "round.id": "local-dev",
                    "task.id": str(task_id),
                },
                "project_name": project_name,
                "source": [
                    {
                        "sha256": projects_sha256,
                        "type": "fuzz-tooling",
                        "url": f"file:///crs/local_files/projects.tar.gz"
                    },
                    {
                        "sha256": repo_sha256,
                        "type": "repo",
                        "url": f"file:///crs/local_files/{project_name}/repo.tar.gz"
                    }
                ],
                "task_id": str(task_id),
                "type": "full"
            }
        ]
    }
    
    # Write the task file
    with open(output_path, "w") as f:
        json.dump(task_data, f, indent=2)
    
    print(f"Created task file: {output_path}")
    print(f"Projects tar: {projects_tar_path}")
    print(f"Repo tar: {repo_tar_path}")

def main():
    parser = argparse.ArgumentParser(description="Create local task JSON for any project")
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument("--projects-tar", default="local_files/projects.tar.gz", 
                       help="Path to projects.tar.gz file")
    parser.add_argument("--output-dir", default="tests/app/tasks", 
                       help="Output directory for task JSON files")
    
    args = parser.parse_args()
    
    # Paths
    projects_tar_path = Path(args.projects_tar)
    local_files_dir = Path("local_files")
    project_dir = local_files_dir / args.project_name
    repo_tar_path = project_dir / "repo.tar.gz"
    tasks_dir = Path(args.output_dir) / args.project_name
    output_path = tasks_dir / "full-local.json"
    
    # Check if projects.tar.gz exists
    if not projects_tar_path.exists():
        print(f"Error: {projects_tar_path} not found.")
        print("Run 'create_tasks.py' first to create the projects.tar.gz file.")
        return 1
    
    # Create directories
    project_dir.mkdir(parents=True, exist_ok=True)
    tasks_dir.mkdir(parents=True, exist_ok=True)
    
    # Create dummy repo tar if it doesn't exist
    if not repo_tar_path.exists():
        print(f"Creating dummy repo tar: {repo_tar_path}")
        create_dummy_repo_tar(args.project_name, repo_tar_path)
    
    # Create task JSON
    create_task_json(args.project_name, projects_tar_path, repo_tar_path, output_path)
    
    print(f"\nTask created successfully for project: {args.project_name}")
    print(f"Submit with: curl -X POST http://localhost:1323/v1/task/ -H 'Content-Type: application/json' -d @{output_path}")
    
    return 0

if __name__ == "__main__":
    exit(main())
