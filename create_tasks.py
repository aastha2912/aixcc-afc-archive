import argparse
import asyncio
import datetime
import os
import pathlib

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

def getenv(name: str):
    res = os.getenv(name)
    if not res:
        raise Exception(f"Must set {name} to use this script")
    return res

CONTAINER_NAME = getenv("CONTAINER_NAME")
STORAGE_ACCOUNT = getenv("STORAGE_ACCOUNT")
STORAGE_KEY = getenv("STORAGE_KEY")
CONNECTION_STRING = getenv("CONNECTION_STRING")

async def upload_blob(artifact: Path) -> tuple[str, str]:
    def compute_hash():
        with open(artifact, "rb") as f:
            return file_digest(f, "sha256").hexdigest()
    shasum = await asyncio.to_thread(compute_hash)

    blob_name = f"{shasum}-{artifact.name}"
    logger.info(f"Uploading {blob_name}...")
    async with process.scope() as scope:
        proc = await scope.exec(*[
            "az", "storage", "blob", "upload",
            "--container-name", CONTAINER_NAME,
            "--account-name", STORAGE_ACCOUNT,
            "--file", artifact.as_posix(),
            "--name", blob_name,
            "--sas-token", STORAGE_KEY,
        ], stdout=PIPE, stderr=PIPE)
        _, stderr = await proc.communicate()
        if proc.returncode != 0 and b"already exists" not in stderr:
            raise Exception(f"Error uploading blob: {stderr}")

        proc = await scope.exec(*[
            "az", "storage", "blob", "generate-sas",
            "--account-name", STORAGE_ACCOUNT,
            "--container-name", CONTAINER_NAME,
            "--name", blob_name,
            "--permissions", "r",
            "--expiry", "2100-01-01T00:00:00Z",
            "--output", "tsv",
            "--connection-string", CONNECTION_STRING,
            "--full-uri"
        ], stdout=PIPE, stderr=PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise Exception(f"Error generating sas: {stderr}")
        return shasum, stdout.decode().strip()

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
        shasum, url = await upload_blob(src_tar)
        return SourceDetail(sha256=shasum, type=SourceType.SourceTypeFuzzTooling, url=url)

src_tar_cache: dict[bytes, SourceDetail] = {}
async def get_src_tar_detail(vfs: VFS, repo_path: Path):
    if (key := await vfs.hash()) not in src_tar_cache:
        async with vfs.materialized() as tmpdir:
            async with tar_gz(tmpdir / repo_path, excludes=[f"{repo_path.name}/.git"]) as src_tar:
                shasum, url = await upload_blob(src_tar)
                src_tar_cache[key] = SourceDetail(sha256=shasum, type=SourceType.SourceTypeRepo, url=url)
    return src_tar_cache[key]

async def get_diff_detail(diff: str):
    async with aio.tmpdir() as td:
        diff_dir = td / "diff"
        await diff_dir.mkdir()
        diff_file = diff_dir / "ref.diff"
        _ = await diff_file.write_text(diff)
        async with tar_gz(diff_dir) as diff_tar:
            shasum, url = await upload_blob(diff_tar)
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

async def dump_task_curls(project: TestProject, oss_fuzz_source: SourceDetail):
    task_dir = TASKS_DIR / project.name
    await task_dir.mkdir(parents=True, exist_ok=True)

    repo_path = (await project.repo_path()).unwrap()
    full_src_detail = await get_src_tar_detail(project.vfs, repo_path)
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
        base_src_detail = await get_src_tar_detail(delta_task.base.vfs, repo_path)
        diff_detail = await get_diff_detail(delta_task.diff)
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
    oss_fuzz_source = await get_ossfuzz_detail()
    for project_name in args.projects:
        project_path = PROJECTS_DIR / project_name
        project = await TestProject.from_dir(project_path)
        await dump_task_curls(project, oss_fuzz_source)
    pass

if __name__ == "__main__":
    asyncio.run(main())
