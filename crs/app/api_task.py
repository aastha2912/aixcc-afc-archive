import aiohttp
import aiofile
import asyncio
import tarfile

from hashlib import sha256
from crs.common.aio import Path
from typing import Optional

from crs import config
from crs.common import aio, process, diff_utils
from crs.common.alru import alru_cache
from crs.common.utils import requireable, require
from crs.common.vfs.diff import DiffOverlayFS
from crs.common.vfs.tar import TarFS
from crs.common.types import Ok, Err, Result, CRSError
from crs.modules import project
from crs.modules.coverage import CoverageAnalyzer
from crs.modules.debugger import Debugger
from crs.task_server import models

from crs_rust import logger

HTTP_CHUNK_SIZE = 65536
MAX_BACKOFF_SLEEP = 120

class UnpackException(Exception):
    pass


async def gunzip(filepath: Path, outpath: Path) -> bool:
    if await outpath.exists():
        return True

    async with aio.tmpfile(dir=outpath.parent) as tf:
        async with process.run(
            "gunzip", "-ck", filepath.as_posix(),
            stdin=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            stdout=tf,
        ) as p:
            _, stderr = await p.communicate()
            if await p.wait() != 0:
                logger.error(f"failed to un-gzip {filepath}: {stderr!r}")
                return False

            try:
                # same device so should be atomic and safe...
                await tf.path.rename(outpath)
            except OSError as e:
                logger.error(f"failed to gunzip rename {filepath} -> {outpath}: {e}")
                return False
    return True


_downloaded_files: set[tuple[str, Path, str]] = set()
async def fetch_file(session: aiohttp.ClientSession, url: str, filepath: Path, digest: str):
    if (url, filepath, digest) in _downloaded_files:
        return
    if await filepath.exists():
        return
    backoff = 1

    # retry in case of errors
    while True:
        async with aio.tmpfile(dir=filepath.parent, suffix=".gz") as tf:
            logger.info(f"fetching file {url=} {tf.name=} {filepath=}")
            async with aiofile.async_open(tf.name, "wb") as f:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            logger.error(f"status code {resp.status} when trying to download task file {url}. Sleeping {backoff}s")
                            await asyncio.sleep(backoff)
                            backoff = min(backoff * 2, MAX_BACKOFF_SLEEP)
                            continue

                        # feels like overkill, but I'll be really sad if we mess up the download....
                        h = sha256()
                        async for chunk in resp.content.iter_chunked(HTTP_CHUNK_SIZE):
                            h.update(chunk)
                            if len(chunk) != await f.write(chunk):
                                logger.error(f"short write when trying to download task file {url} to {filepath}!? Sleeping {backoff}s")
                                await asyncio.sleep(backoff)
                                backoff = min(backoff * 2, MAX_BACKOFF_SLEEP)
                                continue

                        if h.hexdigest() != digest.strip():
                            if "tjbeckertest" in url:
                                logger.warning(f"hash mismatch, ignoring because it's from our test url")
                            else:
                                logger.error(f"hash mismatch when trying to download task file {url}!? Sleeping {backoff}s")
                                await asyncio.sleep(backoff)
                                backoff = min(backoff * 2, MAX_BACKOFF_SLEEP)
                                continue

                        if await gunzip(tf.path, filepath):
                            # all done
                            return
                except aiohttp.ClientError as e:
                    logger.error(f"connection failure to {url}: {e}!? Sleeping {backoff}s")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF_SLEEP)


def extract_tar_dir(tar_path: Path) -> str:
    # grab the top-level "folder" quickly: everything in the tar is a subfolder of one
    # thing which is the repo we care about
    with tarfile.TarFile(tar_path.as_posix()) as tf:
        ti = tf.next()
        assert ti, "tar is empty!"
        return Path(ti.name).parts[0]

@alru_cache(maxsize=None)
async def extract_oss_fuzz_folder(oss_fuzz_sha256: str, oss_fuzz_tar: Path, project: str) -> Path:
    oss_fuzz_dir = extract_tar_dir(oss_fuzz_tar)

    # may overwrite files with themselves in cases of weird races; not really a concern
    base = config.CACHE_DIR / f"oss_fuzz_{oss_fuzz_sha256}"
    outpath = base / oss_fuzz_dir / "projects" / project

    if await outpath.exists():
        return outpath

    await outpath.parent.mkdir(parents=True, exist_ok=True)

    async with aio.tmpdir(dir=base) as td:
        async with process.run(
            "tar", "-xf", oss_fuzz_tar.as_posix(), "--directory", str(td), f"{oss_fuzz_dir}/projects/{project}",
            stdin=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        ) as p:
            stdout, stderr = await p.communicate()
            if await p.wait() != 0:
                logger.error(f"failed to extract {oss_fuzz_dir}/projects/{project} from {oss_fuzz_tar}: {stdout!r}\n{stderr!r}")
                raise UnpackException("failed to extract oss fuzz")

            await (td / oss_fuzz_dir / "projects" / project).rename(outpath)
            return outpath

def extract_diff_thread(diff_sha256: str) -> bytes:
    with tarfile.TarFile( (config.CACHE_DIR / diff_sha256).with_suffix(".tar") ) as difftar:
        for mi in difftar.getmembers():
            if mi.isreg():
                if extracted := difftar.extractfile(mi):
                    return extracted.read()
        raise UnpackException("failed to find and extract diff!")

@alru_cache(maxsize=None)
async def extract_diff(project_folder: Path, diff_sha256: str) -> Path:
    outpath = (project_folder / diff_sha256).with_suffix(".diff")
    if await outpath.exists():
        return outpath

    await outpath.parent.mkdir(parents=True, exist_ok=True)

    async with aio.tmpfile(dir=project_folder) as tf:
        diff = await asyncio.to_thread(extract_diff_thread, diff_sha256)
        _ = await tf.path.write_bytes(diff)
        await tf.path.rename(outpath)
        return outpath

@requireable
async def rewrite_diff(project: project.Project, diff: str):
    base_path = require(await project.repo_path())
    def rewrite_path(line: str, prev: str, post: str):
        if line.startswith("diff") or line.startswith("---") or line.startswith("+++"):
            line = line.replace(f"a/{prev}", f"a/{(base_path / prev).as_posix()}")
            return line.replace(f"b/{post}", f"b/{(base_path / post).as_posix()}")
        else:
            return line
    def rewrite_section(section: str, prev: str, post: str):
        return "".join(rewrite_path(l, prev, post) for l in section.splitlines(keepends=True))
    return Ok(diff_utils.filter_diff(diff, rewrite_section))

async def api_to_crs_task(task_detail: models.TaskDetail) -> Result[project.Task]:
    async with aiohttp.ClientSession() as session:
        async with asyncio.TaskGroup() as tg: # TODO: switch to gather because of scary bugs
            project_folder = config.CACHE_DIR / task_detail.project_name
            for source in task_detail.source:
                dst = (config.CACHE_DIR / source.sha256).with_suffix(".tar")
                _ = tg.create_task(
                    fetch_file(session, source.url, dst, source.sha256),
                    name=f"fetch_file(url={source.url}, path={dst}) project={task_detail.project_name}",
                )

    project_folder = config.CACHE_DIR / task_detail.project_name

    # after the fetch_file completed, this will have the files
    details: dict[models.SourceType, models.SourceDetail] = {}
    for source in task_detail.source:
        details[source.type] = source

    assert models.SourceType.SourceTypeRepo in details, "task must have a repo!"
    assert models.SourceType.SourceTypeFuzzTooling in details, "task must have fuzz tooling!"

    # extract the tar for the fuzz tooling and diff (if applicable)
    diff_file: Optional[Path] = None
    try:
        source = details[models.SourceType.SourceTypeFuzzTooling]
        oss_fuzz_dir = await extract_oss_fuzz_folder(
            source.sha256,
            (config.CACHE_DIR / source.sha256).with_suffix(".tar"),
            task_detail.project_name
        )

        if diff_details := details.get(models.SourceType.SourceTypeDiff):
            diff_file = await extract_diff(project_folder, diff_details.sha256)
    except Exception as e:
        return Err(CRSError(f"failed to make ossfuzz directory: {e}"))

    repo_detail = details[models.SourceType.SourceTypeRepo]
    repo_tar_path = (config.CACHE_DIR / repo_detail.sha256).with_suffix(".tar")

    repo_folder = extract_tar_dir(repo_tar_path)

    raw_project = await project.Project.from_dir(oss_fuzz_dir, ossfuzz_hash=source.sha256)
    source_vfs = await TarFS.fsopen(repo_tar_path)
    match await raw_project.fork_with_source(source_vfs, repo_folder):
        case Ok(base): pass
        case Err(e):
            return Err(CRSError(f"failed to fork project with source code: {e.error}"))

    if diff_file and diff_details:
        diff_vfs = DiffOverlayFS(source_vfs, diff_file, repo_folder)
        match await raw_project.fork_with_source(diff_vfs, repo_folder):
            case Ok(diff_proj): pass
            case Err(e):
                return Err(CRSError(f"failed to fork project with diff source code: {e.error}"))
        match await rewrite_diff(diff_proj, await diff_file.read_text(errors="replace")):
            case Ok(rewritten_diff): pass
            case Err(e):
                return Err(CRSError(f"failed to rewrite diff: {e.error}"))
        return Ok(project.DeltaTask(
            task_detail.task_id, task_detail.deadline, diff_proj, CoverageAnalyzer(diff_proj),
            Debugger(diff_proj), task_detail.metadata, base, rewritten_diff
        ))
    else:
        return Ok(
            project.Task(
                task_detail.task_id, task_detail.deadline, base,
                CoverageAnalyzer(base), Debugger(base), task_detail.metadata
            )
        )
