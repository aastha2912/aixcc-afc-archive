import asyncio
import os
import tarfile
import io
import stat

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from dataclasses import dataclass
from functools import partial
from hashlib import file_digest
from crs.common.aio import Path
from typing import Callable, Optional, Self

from .base import VFS, Layer, CommandLayer, TarFileLayer, TarBytesLayer, vfs_counter
from crs.common.alru import alru_cache, async_once

_DUMMY = tarfile.open(mode="w", fileobj=io.BytesIO())
def gettarinfo(name: str, arcname: Optional[str] = None):
    return _DUMMY.gettarinfo(name, arcname=arcname)

DEFAULT_MODE = 0o100644

def extract_contents(tar: tarfile.TarFile, info: tarfile.TarInfo) -> bytes:
    fp = tar.extractfile(info)
    assert fp is not None
    with fp as f:
        return f.read()

tar_executor = ThreadPoolExecutor(4, "async_tar")

class AsyncioTarFile:
    """
    NOTE: assumes the file at `path` is immutable
    """
    path: Path
    executor: ThreadPoolExecutor
    tar: tarfile.TarFile

    def __init__(self, path: Path, tar: tarfile.TarFile):
        self.path = path
        self.tar = tar
        self.lock = asyncio.Lock()

    @classmethod
    async def open(cls, path: Path) -> Self:
        tar = await asyncio.to_thread(tarfile.open, path, "r:")
        return cls(path, tar)

    async def _execute[*P, R](self, func: Callable[[*P], R], *args: *P) -> R:
        async with self.lock:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(tar_executor, func, *args)

    @async_once
    async def members(self):
        vfs_counter.add(1, {"type": "tar", "op": "getmembers"})
        def compute():
            member_list = self.tar.getmembers()
            return {os.path.normpath(m.name): m for m in member_list}
        return await self._execute(compute)

    async def get_member(self, path: str) -> tarfile.TarInfo:
        members = await self.members()
        tarinfo = members.get(os.path.normpath(path), None)
        if tarinfo is None:
            raise KeyError("filename %r not found" % path)
        return tarinfo

    async def getnames(self):
        return (await self.members()).keys()

    Filter = Callable[[tarfile.TarInfo, str], tarfile.TarInfo | None]
    async def extractall(self, path: str | Path, filter: Optional[Filter]):
        return await self._execute(partial(self.tar.extractall, filter=filter), path)

    def __del__(self):
        self.tar.close()

    async def extract_contents(self, info: tarfile.TarInfo):
        def read():
            file = self.tar.extractfile(info)
            assert file is not None
            with file as f:
                return f.read()
        return await self._execute(read)

class TarFS(VFS):
    path: Path
    tar: AsyncioTarFile

    def __init__(self, path: Path, tar: AsyncioTarFile):
        self.path = path
        self.tar = tar

    @classmethod
    async def fsopen(cls, path: Path) -> Self:
        tar = await AsyncioTarFile.open(path)
        return cls(path, tar)

    @classmethod
    def _unpickle(cls, path: Path) -> Self:
        tar = tarfile.open(path, "r:")
        return cls(path, AsyncioTarFile(path, tar))

    def __reduce__(self):
        return (TarFS._unpickle, (self.path, ))

    async def _resolve(self, path: str):
        vfs_counter.add(1, {"type": "tar", "op": "_resolve"})
        visited: set[str] = set()
        while path not in visited:
            visited.add(path)
            try:
                info = await self.tar.get_member(path)
            except KeyError:
                # if the path does not exist in the tar, return it as-is
                return path
            if not info.islnk():
                # if the path is not a symlink, return it as-is
                return path
            # otherwise, traverse symlink and continue
            path = os.path.normpath(os.path.join(os.path.dirname(path), info.linkname))
        else:
            raise RuntimeError("symlink loop")

    async def read(self, path: str) -> bytes:
        vfs_counter.add(1, {"type": "tar", "op": "read"})
        return await self.tar.extract_contents(await self.tar.get_member(path))

    async def write(self, path: str, data: bytes) -> None:
        vfs_counter.add(1, {"type": "tar", "op": "write"})
        raise NotImplementedError

    async def is_file(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "tar", "op": "is_file"})
        try:
            info = await self.tar.get_member(path)
        except KeyError:
            return False
        return info.isfile()

    async def is_dir(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "tar", "op": "is_dir"})
        try:
            info = await self.tar.get_member(path)
        except KeyError:
            return False
        return info.isdir()

    async def is_exe(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "tar", "op": "is_exe"})
        try:
            info = await self.tar.get_member(path)
        except KeyError:
            return False
        return info.isfile() and (info.mode & 0o100) != 0

    async def mode(self, path: str) -> Optional[int]:
        vfs_counter.add(1, {"type": "tar", "op": "mode"})
        try:
            info = await self.tar.get_member(path)
        except KeyError:
            return None
        return info.mode

    @alru_cache(maxsize=None)
    async def _hash(self) -> bytes:
        vfs_counter.add(1, {"type": "tar", "op": "_hash"})
        def compute():
            with open(self.path, "rb") as f:
                return file_digest(f, "sha256").digest()
        return await asyncio.to_thread(compute)

    async def hash(self) -> bytes:
        return await self._hash()

    async def layers(self) -> tuple[Layer, ...]:
        vfs_counter.add(1, {"type": "tar", "op": "layers"})
        return (TarFileLayer(".", ".", self.path), )

@dataclass(frozen=True, slots=True)
class File:
    info: tarfile.TarInfo
    contents: bytes

    def hash(self):
        data = (self.contents, self.info.mode, self.info.size)
        return sha256(repr(data).encode()).digest()

class EditableOverlayFS(VFS):
    parent: VFS
    files: dict[str, File]
    deleted: set[str]

    def __init__(self, parent: VFS):
        self.parent = parent
        self.files = {}
        self.deleted = set()
        self._hash: Optional[bytes] = None # cached hash value

    def _resolve(self, path: str):
        vfs_counter.add(1, {"type": "editable", "op": "_resolve"})
        path = os.path.normpath(path)
        visited: set[str] = set()
        while True:
            if path in visited:
                raise RuntimeError("symlink loop")
            visited.add(path)
            if path in self.deleted:
                return path
            if (file := self.files.get(path)) is None:
                return path
            if not file.info.islnk():
                return path
            # traverse symlink
            path = os.path.normpath(os.path.join(os.path.dirname(path), file.info.linkname))

    def fork(self):
        new = EditableOverlayFS(self.parent)
        new.files = self.files.copy()
        new.deleted = self.deleted.copy()
        return new

    async def read(self, path: str) -> bytes:
        vfs_counter.add(1, {"type": "editable", "op": "read"})
        path = self._resolve(path)
        if path in self.deleted:
            raise FileNotFoundError("File was deleted in overlay")
        if (file := self.files.get(path)) is not None:
            return file.contents
        return await self.parent.read(path)

    async def populate(self, host_path: Path):
        vfs_counter.add(1, {"type": "editable", "op": "populate"})
        async with host_path.walk() as it:
            async for root, _, files in it:
                for f in files:
                    path = (root / f)
                    relative = path.relative_to(host_path).as_posix()
                    info = gettarinfo(path.as_posix(), arcname=relative)
                    self.deleted.discard(relative)
                    self.files[relative] = File(info, b"" if await path.is_symlink() else await path.read_bytes())
        self._hash = None

    async def write(self, path: str, data: bytes) -> None:
        vfs_counter.add(1, {"type": "editable", "op": "write"})
        path = os.path.normpath(path)
        info = tarfile.TarInfo(path)
        if (mode := await self.parent.mode(path)) is None:
            mode = DEFAULT_MODE
        info.mode = mode
        info.size = len(data)
        self.deleted.discard(path)
        self.files[path] = File(info, data)
        self._hash = None

    def link(self, path: str, dst: str) -> None:
        vfs_counter.add(1, {"type": "editable", "op": "link"})
        path = os.path.normpath(path)
        assert not os.path.isabs(dst), "cannot link to an absolute path"
        info = tarfile.TarInfo(path)
        info.type = tarfile.SYMTYPE
        info.linkname = dst
        self.deleted.discard(path)
        self.files[path] = File(info, b"")
        self._hash = None

    def delete(self, path: str) -> None:
        vfs_counter.add(1, {"type": "editable", "op": "delete"})
        path = os.path.normpath(path)
        self.deleted.add(path)
        self._hash = None

    async def is_file(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "editable", "op": "is_file"})
        path = os.path.normpath(path)
        if (file := self.files.get(path)) is not None:
            return file.info.isreg()
        return await self.parent.is_file(path)

    async def is_dir(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "editable", "op": "is_dir"})
        return await self.parent.is_dir(path)

    async def is_exe(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "editable", "op": "is_exe"})
        path = os.path.normpath(path)
        if (file := self.files.get(path)) is not None:
            return bool(file.info.mode & stat.S_IXUSR)
        return await self.parent.is_exe(path)

    async def mode(self, path: str) -> Optional[int]:
        vfs_counter.add(1, {"type": "editable", "op": "mode"})
        path = os.path.normpath(path)
        if (file := self.files.get(path)) is not None:
            return file.info.mode
        return await self.parent.mode(path)

    def _compute_hash(self, parent_hash: bytes) -> bytes:
        vfs_counter.add(1, {"type": "editable", "op": "_compute_hash"})
        if len(self.files) == 0:
            return parent_hash
        data = [(k, v.hash()) for k,v in sorted(self.files.items())] + list(self.deleted)
        return sha256(parent_hash + repr(data).encode()).digest()

    async def hash(self) -> bytes:
        if self._hash is None:
            self._hash = self._compute_hash(await self.parent.hash())
        return self._hash

    async def layers(self) -> tuple[Layer, ...]:
        vfs_counter.add(1, {"type": "editable", "op": "layers"})
        res = await self.parent.layers()
        if len(self.files) == 0:
            return res

        # TODO: manually build the tar byte stream?
        buf = io.BytesIO()
        with tarfile.open(mode="w", fileobj=buf) as tar:
            for _, file in self.files.items():
                tar.addfile(file.info, None if file.info.islnk() else io.BytesIO(file.contents))
        _ = buf.seek(0)
        res += (TarBytesLayer(".", ".", buf), )
        if len(self.deleted) > 0:
            res += (CommandLayer(".", ".", ("rm", "-rf") + tuple(self.deleted)), )
        return res
