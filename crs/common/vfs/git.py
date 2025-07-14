import asyncio
import os
import pygit2
import string
import zlib

from .base import VFS, Layer, CommandLayer, vfs_counter
from crs.common.alru import async_once
from crs.common.utils import Executor

from functools import partial, wraps
from hashlib import sha256
from crs.common.aio import Path
from typing import Any, Callable, Concatenate, Coroutine, Iterator, Optional, Tuple

from crs_rust import logger

GIT_TYPEMAP: dict[bytes, int] = {
    b"commit": pygit2.GIT_OBJECT_COMMIT, # type: ignore
    b"tree": pygit2.GIT_OBJECT_TREE, # type: ignore
    b"blob": pygit2.GIT_OBJECT_BLOB, # type: ignore
    b"tag": pygit2.GIT_OBJECT_TAG, # type: ignore
}

def is_git_hash(ref: str):
    return len(ref) == 40 and set(ref).issubset(string.hexdigits)

class VFSOdbBackend(pygit2.OdbBackend):
    def __init__(self, vfs: VFS, repo_path: str, executor: Executor):
        super().__init__() # type: ignore
        self._vfs = vfs
        self._repo_path = repo_path
        self._executor = executor

    def _obj_path(self, oid: pygit2.Oid) -> str:
        hex_oid = str(oid)
        return os.path.join(self._repo_path, ".git/objects", hex_oid[:2], hex_oid[2:])

    def read_cb(self, oid: pygit2.Oid) -> Tuple[int, bytes]:
        vfs_counter.add(1, {"type": "git", "op": "read_cb"})
        compressed_data = self._executor.execute_coro(self._vfs.read(self._obj_path(oid)))
        decompressed_data = zlib.decompress(compressed_data)
        type, rest = decompressed_data.split(b' ', maxsplit=1)
        _, rest = rest.split(b"\x00", maxsplit=1)
        return (GIT_TYPEMAP[type], rest)

    def read_prefix_cb(self, short_oid: str) -> Tuple[int, bytes, pygit2.Oid]:
        if not is_git_hash(short_oid):
            raise NotImplementedError
        oid = pygit2.Oid(hex=short_oid)
        return *self.read_cb(oid), oid

    def read_header_cb(self, short_oid: str) -> Optional[Tuple[bytes, int]]:
        raise NotImplementedError

    def exists_cb(self, oid: pygit2.Oid) -> bool:
        return self._executor.execute_coro(self._vfs.is_file(self._obj_path(oid)))

    def exists_prefix_cb(self, oid: pygit2.Oid) -> bool:
        raise NotImplementedError

    def write_cb(self, data: bytes, type: int) -> pygit2.Oid:
        raise NotImplementedError

    def refresh_cb(self) -> None:
        pass

    def __iter__(self) -> Iterator[pygit2.Oid]:
        raise NotImplementedError
        yield None

class VFSRefdbBackend(pygit2.RefdbBackend):
    def __init__(self, vfs: VFS, repo_path: str, executor: Executor):
        """
        :param tar: An open tarfile.TarFile object for the entire repo.
        """
        super().__init__() # type: ignore
        self._vfs = vfs
        self._repo_path = repo_path
        self._executor = executor
        self._refs: dict[str, str] = {}

    @async_once
    async def _init(self):
        vfs_counter.add(1, {"type": "git", "op": "_init"})
        try:
            raw = await self._vfs.read(os.path.join(self._repo_path, ".git/HEAD"))
            data = raw.decode(errors="replace")
            if data.startswith("ref:"):
                # e.g. "ref: refs/heads/main"
                head_ref = data.split(":", 1)[1].strip()
                # We'll store HEAD => that ref, so that _resolve_ref("HEAD") works
                self._refs["HEAD"] = head_ref
            else:
                # It's just a commit SHA
                self._refs["HEAD"] = data
        except Exception as e:
            logger.warning(f"eror reading .git/HEAD: {repr(e)}")
            pass

    async def read_ref(self, ref: str) -> Optional[str]:
        if (res := self._refs.get(ref)) is not None:
            return res
        ref_path = os.path.join(self._repo_path, ".git", ref)
        try:
            data = await self._vfs.read(ref_path)
            res = self._refs[ref] = data.decode(errors="replace").strip()
            return res
        except Exception as e:
            logger.warning(f"error reading {ref_path}: {repr(e)}")

    async def _resolve_ref_async(self, ref: Optional[str]) -> Optional[str]:
        await self._init()
        visited: set[str] = set()
        while ref is not None:
            if is_git_hash(ref):
                return ref.lower()
            if ref in visited:
                return None # cyclical? (very unlikely in real usage)
            visited.add(ref)
            ref = await self.read_ref(ref)

    def _resolve_ref(self, ref: str) -> Optional[str]:
        return self._executor.execute_coro(self._resolve_ref_async(ref))

    def lookup(self, refname: str):
        return pygit2.Reference(refname, self._resolve_ref(refname))

    def compress(self) -> None:
        raise NotImplementedError

    def delete(self, ref_name: str, old_id: str | pygit2.Oid, old_target: str) -> None:
        raise NotImplementedError

    def ensure_log(self, ref_name: str) -> bool:
        raise NotImplementedError

    def exists(self, refname: str) -> bool:
        raise NotImplementedError

    def has_log(self, ref_name: str) -> bool:
        raise NotImplementedError

    def rename(
        self, old_name: str, new_name: str, force: bool, who: pygit2.Signature, message: str
    ) -> pygit2.Reference:
        raise NotImplementedError

    def write(
        self,
        ref: pygit2.Reference,
        force: bool,
        who: pygit2.Signature,
        message: str,
        old: str | pygit2.Oid,
        old_target: str,
    ) -> None:
        raise NotImplementedError

    def __iter__(self) -> Iterator[str]:
        raise NotImplementedError

    # RefdbBackend.__init__ does PyIter_Check(self), which requires a __next__ method to pass
    # this seems like a bug in pygit2
    def __next__(self): # type: ignore
        raise NotImplementedError

class GitTree:
    def __init__(self, vfs: VFS, repo_path: str, ref: str, executor: Executor):
        self._vfs = vfs
        self._repo_path = repo_path
        self._ref = ref
        self._executor = executor

        self._repo = pygit2.repository.Repository()

        self._odb = pygit2.Odb()
        self._odb.add_backend(VFSOdbBackend(vfs, repo_path, executor), 0)
        self._repo.set_odb(self._odb)

        self._refdb = pygit2.Refdb.open(self._repo)
        self._refdb.set_backend(VFSRefdbBackend(vfs, repo_path, executor))
        self._repo.set_refdb(self._refdb)

        oid = ref if is_git_hash(ref) else self._repo.lookup_reference(ref).target
        obj: pygit2.Object = self._repo.git_object_lookup_prefix(oid)
        assert isinstance(obj, pygit2.Commit), f"ref points to invalid object type {type(obj)}"
        self._commit = obj

    @staticmethod
    def use_executor[**P, R](
        func: Callable[Concatenate['GitTree', P], R]
    ) -> Callable[Concatenate['GitTree', P], Coroutine[Any, Any,  R]]:
        @wraps(func)
        async def wrapper(self: 'GitTree', *args: P.args, **kwargs: P.kwargs) -> R:
            return await self._executor.execute_sync(partial(func, self, *args, **kwargs))
        return wrapper

    @use_executor
    def get_entry(self, path: str | Path) -> pygit2.Object:
        tree = self._commit.tree
        path = Path(path)
        try:
            parts = path.relative_to(self._repo_path).parts
        except ValueError:
            raise FileNotFoundError(f"Path '{path}' not found in tree.")
        while len(parts) > 0:
            part, parts = parts[0], parts[1:]
            for entry in tree:
                if entry.name != part:
                    continue
                if len(parts) == 0:
                    return entry
                else:
                    if isinstance(entry, pygit2.Tree):
                        tree = entry
                        break
                    else:
                        raise TypeError(f"Expected a tree, found {entry.__class__.__name__} at {entry.name}")
            else:
                raise FileNotFoundError(f"Path component '{part}' not found in tree.")
        raise FileNotFoundError(f"Path '{path}' not found in tree.")

    @use_executor
    def get_data(self, blob: pygit2.Blob) -> bytes:
        return blob.data

    def commit_id(self) -> str:
        return str(self._commit.id)

class GitTreeFS(VFS):
    def __init__(self, vfs: VFS, repo_path: str, ref: str):
        self._vfs = vfs
        self._repo_path = repo_path
        self._ref = ref

    def __reduce__(self):
        return (GitTreeFS, (self._vfs, self._repo_path, self._ref))

    @async_once
    async def git_tree(self) -> GitTree:
        assert (loop := asyncio.get_running_loop()) is not None
        executor = Executor(loop, "git_tree")
        return await executor.execute_sync(GitTree, self._vfs, self._repo_path, self._ref, executor)

    async def get_entry(self, path: str | Path) -> pygit2.Object:
        tree = await self.git_tree()
        return await tree.get_entry(path)

    async def get_data(self, blob: pygit2.Blob) -> bytes:
        tree = await self.git_tree()
        return await tree.get_data(blob)

    async def read(self, path: str) -> bytes:
        vfs_counter.add(1, {"type": "git", "op": "read"})
        try:
            entry = await self.get_entry(path)
            # This is the final part; must be a blob
            if not isinstance(entry, pygit2.Blob):
                raise TypeError(f"Expected a blob, found {entry.__class__.__name__} at {entry.name}")
            return await self.get_data(entry)
        except FileNotFoundError:
            # TODO: filter out deleted files at ref
            return await self._vfs.read(path)

    async def write(self, path: str, data: bytes) -> None:
        vfs_counter.add(1, {"type": "git", "op": "write"})
        raise NotImplementedError

    async def is_file(self, path: str):
        vfs_counter.add(1, {"type": "git", "op": "is_file"})
        try:
            return isinstance(await self.get_entry(path), pygit2.Blob)
        except FileNotFoundError:
            return await self._vfs.is_file(path)

    async def is_dir(self, path: str):
        vfs_counter.add(1, {"type": "git", "op": "is_dir"})
        try:
            return isinstance(await self.get_entry(path), pygit2.Tree)
        except FileNotFoundError:
            return await self._vfs.is_dir(path)

    async def is_exe(self, path: str):
        vfs_counter.add(1, {"type": "git", "op": "is_exe"})
        try:
            if not isinstance(entry := await self.get_entry(path), pygit2.Blob):
                return False
            return bool(entry.filemode & pygit2.enums.FileMode.BLOB_EXECUTABLE)
        except FileNotFoundError:
            return await self._vfs.is_exe(path)

    async def mode(self, path: str) -> Optional[int]:
        vfs_counter.add(1, {"type": "git", "op": "mode"})
        try:
            entry = await self.get_entry(path)
            if isinstance(entry, pygit2.Blob):
                return entry.filemode
        except FileNotFoundError:
            return await self._vfs.mode(path)
        return None

    async def hash(self) -> bytes:
        vfs_counter.add(1, {"type": "git", "op": "hash"})
        tree = await self.git_tree()
        return sha256(await self._vfs.hash() + tree.commit_id().encode()).digest()

    async def layers(self) -> tuple[Layer, ...]:
        vfs_counter.add(1, {"type": "git", "op": "layers"})
        return await self._vfs.layers() + (CommandLayer(self._repo_path, ".", ("git", "checkout", self._ref)),)
