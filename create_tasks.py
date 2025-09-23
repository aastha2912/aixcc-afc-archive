import argparse
import asyncio
import datetime
import os
import pathlib
import shutil  # (aastham) Added for local file operations

from asyncio.subprocess import PIPE
from contextlib import asynccontextmanager
from hashlib import file_digest
from typing import Optional, AsyncIterator
from uuid import uuid4, UUID

from crs import config
from crs.task_server.models import Task, TaskDetail, TaskType, SourceDetail, SourceType
from crs.modules.testing import TestProject
from crs.common import aio, process
from crs.common.aio import Path
from crs.common.vfs import VFS

VULN_COMMITS = {
    "nginx-asc": { 0, 11, 21, 34, 44, 74, 88, 101, 111, 122, 152, 164, 171, 183 },
    "tomcat-theori": { 38, 39, 40 },
    "curl-theori": { 48, 49 },
    "example-libpng-theori": { 37, 38, 39 },
    "zstd-theori": { 47, 48, 49 },
    "afc-zookeeper": { 40 },
    "afc-libxml2": { 40, 43 },
    "afc-integration-test": { 31 },
    "afc-freerdp": { 40 },
    "afc-commons-compress": { 37, 40 },
    "afc-sqlite3": { 40 },
}

from crs_rust import logger

PROJECTS_DIR = config.CRSROOT / ".." / "projects"
PROJECTS = [dir.name for dir in pathlib.Path(PROJECTS_DIR).iterdir()]
TASKS_DIR = config.CRSROOT / ".." / "tests" / "app" / "tasks"

# (aastham) Local file storage configuration - replaces Azure blob storage for local development
LOCAL_FILES_DIR = config.CRSROOT / ".." / "local_files"

async def save_local_file(artifact: Path, project_name: str = None) -> tuple[str, str]:
    """(aastham) Save file locally and return (sha256, local_file_path) - replaces Azure blob upload"""
    def compute_hash():
        with open(artifact, "rb") as f:
            return file_digest(f, "sha256").hexdigest()
    shasum = await asyncio.to_thread(compute_hash)

    # Create local files directory structure
    if project_name and not artifact.name.startswith("projects"):
        # For project-specific files, create project subdirectory
        project_dir = LOCAL_FILES_DIR / project_name
        try:
            await project_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Directory already exists, that's fine
            logger.info(f"Directory {project_dir} already exists, skipping creation")
        local_file_path = project_dir / artifact.name
    else:
        # For shared files like projects.tar.gz, put in root
        try:
            await LOCAL_FILES_DIR.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Directory already exists, that's fine
            logger.info(f"Directory {LOCAL_FILES_DIR} already exists, skipping creation")
        local_file_path = LOCAL_FILES_DIR / artifact.name
    
    import shutil
    try:
        shutil.copy2(artifact, local_file_path)
    except PermissionError:
        # File already exists, that's fine
        logger.info(f"File {local_file_path} already exists, skipping copy")
    
    # Return local file path that works in Docker container
    # Use relative path from /crs root so it works in both host and container
    relative_path = local_file_path.relative_to(config.CRSROOT.parent)
    local_path = f"file:///crs/{relative_path}"
    
    logger.info(f"Saved {artifact.name} locally to {local_file_path}")
    logger.info(f"Local path: {local_path}")
    
    return shasum, local_path

@asynccontextmanager
async def tar_gz(dir: Path, prefix: Optional[str] = None, excludes: list[str] = []) -> AsyncIterator[Path]:
    assert await dir.is_dir()
    async with aio.tmpdir() as td:
        tar = td / f"{dir.name}.tar.gz"
        cwd = dir.parent
        cmd = [ "tar"] + [a for e in excludes for a in ["--exclude", e]] + ["-czf", tar.as_posix(), dir.name ]
        if prefix:
            cmd.insert(1, f"--transform=s,^,{prefix}/,")
        async with process.run(*cmd, cwd=cwd, stdout=PIPE, stderr=PIPE) as proc:
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise Exception(f"Error tarring src: {stderr}")
        yield tar

async def get_ossfuzz_detail():
    async with tar_gz(PROJECTS_DIR, prefix="theori-test-projects") as src_tar:
        shasum, url = await save_local_file(src_tar)
        return SourceDetail(sha256=shasum, type=SourceType.SourceTypeFuzzTooling, url=url)

src_tar_cache: dict[bytes, SourceDetail] = {}
async def get_src_tar_detail(vfs: VFS, repo_path: Path, project_name: str):
    if (key := await vfs.hash()) not in src_tar_cache:
        async with vfs.materialized() as tmpdir:
            async with tar_gz(tmpdir / repo_path, excludes=[f"{repo_path.name}/.git"]) as src_tar:
                shasum, url = await save_local_file(src_tar, project_name)
                src_tar_cache[key] = SourceDetail(sha256=shasum, type=SourceType.SourceTypeRepo, url=url)
    return src_tar_cache[key]

async def get_diff_detail(diff: str, project_name: str):
    async with aio.tmpdir() as td:
        diff_dir = td / "diff"
        await diff_dir.mkdir()
        diff_file = diff_dir / "ref.diff"
        _ = await diff_file.write_text(diff)
        async with tar_gz(diff_dir) as diff_tar:
            shasum, url = await save_local_file(diff_tar, project_name)
            return SourceDetail(sha256=shasum, type=SourceType.SourceTypeDiff, url=url)

def make_task(task_id: UUID, project_name: str, focus: str, source: list[SourceDetail], type: TaskType):
    now = datetime.datetime.now(datetime.timezone.utc)
    return Task(
        message_id=uuid4(),
        message_time=int(now.timestamp() * 1000),
        tasks=[TaskDetail(
            deadline=int((now + datetime.timedelta(days=365)).timestamp() * 1000),
            focus=focus,
            harnesses_included=True,
            metadata={
                "round.id": "local-dev",
                "task.id": str(task_id),
            },
            project_name=project_name,
            source=source,
            task_id=task_id,
            type=type
        )]
    )

async def write_task(path: Path, task: Task):
    _ = await path.write_bytes(task.model_dump_json().encode())
    logger.info(f"Wrote task to {await path.resolve()}")

async def create_repo_tar(project_path: Path, project_name: str) -> tuple[Path, str, str]:
    """(aastham) Create repo tar directly from project source (skip Docker build)"""
    async with tar_gz(project_path, excludes=[".git", "__pycache__", "*.pyc"]) as repo_tar:
        shasum, local_path = await save_local_file(repo_tar, project_name)
        logger.info(f"Created repo tar for {project_name}: {local_path}")
        return repo_tar, shasum, local_path

async def dump_task_curls_simple(project_name: str, repo_sha256: str, repo_url: str, oss_fuzz_source: SourceDetail):
    """(aastham) Create task JSON for a project without Docker build"""
    oss_fuzz_sha256 = oss_fuzz_source.sha256
    oss_fuzz_url = oss_fuzz_source.url
    
    # Create task
    task = Task(
        message_id=uuid4(),
        message_time=int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000),
        tasks=[
            TaskDetail(
                deadline=int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).timestamp() * 1000),
                focus=project_name,
                harnesses_included=True,
                metadata={"round.id": "local-dev", "task.id": str(uuid4())},
                project_name=project_name,
                source=[
                    SourceDetail(sha256=oss_fuzz_sha256, type="fuzz-tooling", url=oss_fuzz_url),
                    SourceDetail(sha256=repo_sha256, type="repo", url=repo_url),
                ],
                task_id=str(uuid4()),
                type="full",
            )
        ],
    )
    
    # Write task file
    task_path = TASKS_DIR / project_name / "full-local.json"
    await task_path.parent.mkdir(parents=True, exist_ok=True)
    await write_task(task_path, task)

async def dump_task_curls(project: TestProject, oss_fuzz_source: SourceDetail):
    task_dir = TASKS_DIR / project.name
    await task_dir.mkdir(parents=True, exist_ok=True)

    repo_path = (await project.repo_path()).unwrap()
    full_src_detail = await get_src_tar_detail(project.vfs, repo_path, project.name)
    task = make_task(
        (await project.task()).task_id,
        project.name,
        repo_path.name,
        [oss_fuzz_source, full_src_detail],
        TaskType.TaskTypeFull
    )
    await write_task(task_dir / "full.json", task)

    for i, delta_task in enumerate((await project.tasks(rewrite_paths=False)).unwrap()):
        if i not in VULN_COMMITS[project.name]:
            continue
        base_src_detail = await get_src_tar_detail(delta_task.base.vfs, repo_path, project.name)
        diff_detail = await get_diff_detail(delta_task.diff, project.name)
        task = make_task(
            delta_task.task_id,
            project.name,
            repo_path.name,
            [oss_fuzz_source, base_src_detail, diff_detail],
            TaskType.TaskTypeDelta
        )
        await write_task(task_dir / f"delta-{i}.json", task)


async def main():
    parser = argparse.ArgumentParser(description="Test project to API task converter")
    _ = parser.add_argument(
        "--projects",
        type=str,
        nargs="*",
        default=PROJECTS,
        help="The project(s) to run on",
        choices=PROJECTS
    )
    args = parser.parse_args()
    
    # Create local files directory
    await LOCAL_FILES_DIR.mkdir(parents=True, exist_ok=True)
    
    oss_fuzz_source = await get_ossfuzz_detail()
    for project_name in args.projects:
        project_path = PROJECTS_DIR / project_name
        # Create repo tar directly from project source (skip Docker build)
        repo_tar_path, repo_sha256, repo_url = await create_repo_tar(project_path, project_name)
        await dump_task_curls_simple(project_name, repo_sha256, repo_url, oss_fuzz_source)
    
    logger.info(f"Created tasks for projects: {args.projects}")
    logger.info(f"Local files stored in: {LOCAL_FILES_DIR}")
    logger.info("Tasks created with local file paths - no HTTP server needed!")

if __name__ == "__main__":
    asyncio.run(main())
