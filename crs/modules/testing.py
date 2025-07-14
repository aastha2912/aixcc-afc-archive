from asyncio.subprocess import PIPE
from crs.common.aio import Path
from typing import Self, Optional
import hashlib
import time
import uuid

from crs import config

from crs.common import docker, process
from crs.common.alru import async_once, alru_cache
from crs.common.utils import requireable, require
from crs.common.vfs import GitTreeFS
from crs.common.types import Result, Ok, Err, CRSError
from crs.modules.coverage import CoverageAnalyzer
from crs.modules.debugger import Debugger
from crs.modules.project import DeltaTask, Project, Task
from crs.modules.python_sandbox import SANDBOX_IMAGE_NAME

DEFAULT_TASK_TIMEOUT = 4*60*60
TASK_INIT_TIMEOUT = 60*60

TEST_PROJECT_NAMESPACE = uuid.UUID('fbd71260-ddd4-45bd-805e-9a068ed7eb73')

async def crs_projects_hash(projects_dir: Path) -> str:
    path = (await projects_dir.absolute()).as_posix()
    async with process.scope() as scope:
        proc = await scope.exec("git", "-C", path, "log", "-1", "--pretty=format:'%H'", path, stdout=PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError("could not calculate crs projects dir hash")
        git_hash = stdout

        proc = await scope.exec("git", "-C", path, "diff", path, stdout=PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError("could not calculate crs projects dir hash")
    git_diff = stdout

    h = hashlib.sha256()
    h.update(git_hash)
    h.update(git_diff)
    return h.hexdigest()

class TestProject(Project):
    @classmethod
    async def from_dir(cls, project_dir: str | Path, *, ossfuzz_hash: Optional[str] = None) -> Self:
        assert ossfuzz_hash is None
        ossfuzz_hash = await crs_projects_hash(Path(project_dir).parent)
        return await super(TestProject, cls).from_dir(project_dir, ossfuzz_hash=ossfuzz_hash)

    async def task(self) -> Task:
        """
        get full-mode task
        """
        return Task(
            task_id=uuid.uuid5(TEST_PROJECT_NAMESPACE, self.name),
            deadline=int(time.time() + DEFAULT_TASK_TIMEOUT),
            project=self,
            coverage=CoverageAnalyzer(self),
            debugger=Debugger(self),
            metadata={}
        )


    @async_once
    @requireable
    async def tasks(self, rewrite_paths: bool = True) -> Result[list[DeltaTask]]:
        """
        get list of delta-mode tasks
        """
        @alru_cache(maxsize=None)
        async def fork_at_ref(ref: str) -> Project:
            vfs = GitTreeFS(self.vfs, repo.as_posix(), ref=ref)
            return self.new_fork(vfs=vfs, preserve_gtags=False)

        assert (commit_range := self.info.commit_range) is not None
        repo = require(await self.repo_path())
        async with docker.run(SANDBOX_IMAGE_NAME, mounts={config.CRS_GITATTRIBUTES: "/tmp/gitattributes"}, timeout=TASK_INIT_TIMEOUT) as run:
            require(await docker.vwrite_layers(run, "/src", await self.vfs.layers()))
            repo_path = Path("/src") / repo
            docker_args = ["-w", repo_path.as_posix()]
            cmd = ["git", "rev-list", "--first-parent", f"{commit_range.start_ref}^!", commit_range.end_ref]
            proc = await run.exec(*cmd, docker_args=docker_args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                return Err(CRSError(f"git rev-list failed: {stderr.decode(errors="replace")}"))
            tasks: list[DeltaTask] = []
            hashes = list(reversed(stdout.decode(errors="replace").strip().splitlines()))
            for parent_hash, commit_hash in zip(hashes, hashes[1:]):
                cmd = (
                    [ "git", "-c", "core.attributesFile=/tmp/gitattributes", "diff" ] +
                    ([f"--src-prefix=a/{repo}/", f"--dst-prefix=b/{repo}/"] if rewrite_paths else []) +
                    [parent_hash, commit_hash]
                )
                proc = await run.exec(*cmd, docker_args=docker_args, stdout=PIPE, stderr=PIPE)
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    return Err(CRSError(f"git diff failed: {stderr.decode(errors="replace")}"))
                diff = stdout.decode(errors="replace")
                proj = await fork_at_ref(commit_hash)
                tasks.append(DeltaTask(
                    task_id=uuid.uuid5(TEST_PROJECT_NAMESPACE, f"{self.name}_{commit_hash}"),
                    deadline=int(time.time() + DEFAULT_TASK_TIMEOUT),
                    project=proj,
                    coverage=CoverageAnalyzer(proj),
                    debugger=Debugger(proj),
                    metadata={},
                    diff=diff,
                    base=await fork_at_ref(parent_hash),
                ))
            return Ok(tasks)
