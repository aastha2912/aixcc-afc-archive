import os
import re
import tarfile

from asyncio.subprocess import PIPE
from itertools import zip_longest
from crs.common.aio import Path
from typing import Generator

from .base import VFS, vfs_counter
from .tar import TarFS, EditableOverlayFS
from crs.common import aio, process
from crs.common.alru import async_once

from crs_rust import logger

GIT_HEADER_RE = re.compile(r"^diff --git (.+) (.+)$", flags=re.MULTILINE)

def split_sections(diff: str) -> Generator[str, None, None]:
    matches = list(GIT_HEADER_RE.finditer(diff))
    for match, next in zip_longest(matches, matches[1:]):
        end = next.start() if next is not None else len(diff)
        start = match.start()
        yield diff[start:end]

def sanitize_diff(diff: str):
    if "\nBinary files " in diff:
        logger.warning("diff contains binary file edits which we will ignore")
    # ignore any sections which are binary file diffs
    return "".join(section for section in split_sections(diff) if "\nBinary files " not in section)

class DiffOverlayFS(VFS):
    """
    Applies a diff on top of another VFS.
    All edited files are stored in memory, but the serialization only contains the
    parent and the diff path.
    Not editable.
    """
    def __init__(self, parent: TarFS, diff_path: Path, repo_path: str):
        self.parent = parent
        self.diff_path = diff_path
        self.repo_path = repo_path
        self.editable = EditableOverlayFS(parent)

    def __reduce__(self):
        return DiffOverlayFS, (self.parent, self.diff_path, self.repo_path)

    @async_once
    async def _init(self):
        vfs_counter.add(1, {"type": "diff", "op": "_init"})
        diff = sanitize_diff(await self.diff_path.read_text(errors="replace"))
        if len(diff.strip()) == 0:
            logger.warning("skipping empty diff")
            return

        async with aio.tmpdir() as tmpdir:
            def strip_path(p: str):
                return p[2:] if p[:2] in {"a/", "b/"} else p
            paths: set[str] = set()
            for match in GIT_HEADER_RE.finditer(diff):
                paths.add(os.path.normpath(os.path.join(self.repo_path, strip_path(match.groups()[0]))))

            # extract the files we need to edit
            def filter(info: tarfile.TarInfo, _: str):
                return info if os.path.normpath(info.path) in paths else None
            await self.parent.tar.extractall(tmpdir, filter=filter)

            cmd = [ "git", "apply", "--reject", "--whitespace=fix", "-" ]
            cwd = os.path.join(tmpdir, self.repo_path)
            async with process.run(*cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=False, cwd=cwd) as p:
                _, stderr = await p.communicate(diff.encode())
                if await p.wait() != 0:
                    raise RuntimeError(f"git apply failed! {p.returncode=}, {stderr=}")

            await self.editable.populate(Path(tmpdir))

            # track deletions
            for p in paths:
                if not await (tmpdir / p).exists():
                    self.editable.delete(p)

    async def read(self, path: str):
        vfs_counter.add(1, {"type": "diff", "op": "read"})
        await self._init()
        return await self.editable.read(path)

    async def write(self, path: str, data: bytes) -> None:
        vfs_counter.add(1, {"type": "diff", "op": "write"})
        # the only edits we store are from the diff application
        raise NotImplementedError

    async def is_file(self, path: str):
        vfs_counter.add(1, {"type": "diff", "op": "is_file"})
        await self._init()
        return await self.editable.is_file(path)

    async def is_dir(self, path: str):
        vfs_counter.add(1, {"type": "diff", "op": "is_dir"})
        await self._init()
        return await self.editable.is_dir(path)

    async def is_exe(self, path: str):
        vfs_counter.add(1, {"type": "diff", "op": "is_exe"})
        await self._init()
        return await self.editable.is_exe(path)

    async def mode(self, path: str):
        vfs_counter.add(1, {"type": "diff", "op": "mode"})
        await self._init()
        return await self.editable.mode(path)

    async def hash(self):
        vfs_counter.add(1, {"type": "diff", "op": "hash"})
        await self._init()
        return await self.editable.hash()

    async def layers(self):
        vfs_counter.add(1, {"type": "diff", "op": "layers"})
        await self._init()
        return await self.editable.layers()
