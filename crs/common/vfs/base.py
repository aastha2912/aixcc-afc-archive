import asyncio
import os
import contextlib
import tarfile

from abc import ABC, abstractmethod
from dataclasses import replace
from hashlib import sha256
from crs.common.aio import Path
from typing import Callable, Literal, AsyncIterator, Tuple, Optional

from crs.common import aio, process
from crs.common.docker import Layer, TarFileLayer, TarBytesLayer, CommandLayer
from crs.common.alru import alru_cache
from crs.common.path import PathSuffixTree
from crs.common.types import Ok
from crs_rust import logger

from crs.config import metrics, CACHE_DIR
vfs_counter = metrics.create_counter("vfs-ops")

VFS_TREE_CACHE_DIR = CACHE_DIR / "trees"
TREE_RETRY_DELAY = 5
MAX_TREE_RETRIES = 5
FileMode = Literal["r", "rb"]

async def apply_layer(path: Path, layer: Layer):
    filt: Optional[Callable[[tarfile.TarInfo, str], Optional[tarfile.TarInfo]]] = None
    if layer.extract_under != ".":
        def extraction_filter(member: tarfile.TarInfo, path: str) -> Optional[tarfile.TarInfo]:
            try:
                newpath = Path(member.name).relative_to(layer.extract_under)
                return member.replace(name=newpath.as_posix())
            except ValueError:
                # not relative to, so don't extract it
                return
        filt = extraction_filter

    match layer:
        case TarFileLayer(path=p, tar_path=tar_path):
            await asyncio.to_thread(lambda: tarfile.open(tar_path).extractall(path / p, filter=filt))
        case TarBytesLayer(path=p, tar_data=tar_data):
            await asyncio.to_thread(lambda: tarfile.open(fileobj=tar_data).extractall(path / p, filter=filt))
        case CommandLayer(path=p, cmd=cmd):
            # TODO: handle error?
            _ = await process.run_to_res(*cmd, cwd=(path / p), capture_output=True)
        case _:
            logger.error(f"unsupported Layer type: {layer.__class__}")
            raise NotImplementedError

class VFS(ABC):
    @abstractmethod
    async def read(self, path: str) -> bytes:
        ...

    @abstractmethod
    async def write(self, path: str, data: bytes) -> None:
        ...

    @abstractmethod
    async def is_file(self, path: str) -> bool:
        ...

    @abstractmethod
    async def is_dir(self, path: str) -> bool:
        ...

    @abstractmethod
    async def is_exe(self, path: str) -> bool:
        ...

    @abstractmethod
    async def mode(self, path: str) -> Optional[int]:
        ...

    @abstractmethod
    async def hash(self) -> bytes:
        """
        The goals are:
        1. hash() should never collide unless the contents are identical
        2. hash() should be useful for caching. Ideally, if you construct the same VFS layers
           and apply the same edits, it should hash the same.
        """
        ...

    @abstractmethod
    async def layers(self) -> tuple[Layer, ...]:
        ...

    @alru_cache()
    async def _tree(self, hash: bytes):
        if not await VFS_TREE_CACHE_DIR.exists():
            await VFS_TREE_CACHE_DIR.mkdir(exist_ok=True)
        cached = VFS_TREE_CACHE_DIR / f"{hash.hex()}.json"
        if await cached.exists():
            logger.info(f"using cached PathSuffixTree {cached}")
            return Ok(await PathSuffixTree.from_path(cached))
        layers = await self.layers()
        tree = await PathSuffixTree.from_layers(layers)
        retries = MAX_TREE_RETRIES
        while tree.is_err() and retries > 0:
            logger.warning(f"error creating PathSuffixTree: {repr(tree.err())}. retrying in {TREE_RETRY_DELAY:.2f}s...")
            await asyncio.sleep(TREE_RETRY_DELAY)
            tree = await PathSuffixTree.from_layers(layers)
            retries -= 1

        match (tree, await cached.exists()):
            case (Ok(t), False):
                async with aio.tmpfile(dir=cached.parent) as f:
                    await t.dump_to_path(f.path)
                    await f.path.replace(cached)
            case _:
                pass

        return tree

    async def tree(self):
        return await self._tree(await self.hash())

    @contextlib.asynccontextmanager
    async def materialized(self) -> AsyncIterator[Path]:
        async with aio.tmpdir() as tmpdir:
            logger.debug(f"materializing {self.__class__.__name__} at {tmpdir}...")
            for layer in await self.layers():
                _ = await apply_layer(tmpdir, layer)
            logger.debug(f"done materializing {self.__class__.__name__} at {tmpdir}")
            yield tmpdir

# TODO: rework to a multi-VFS mount namespace
class MountFS(VFS):
    parent: VFS
    child: VFS
    mount: str
    child_path: str

    def __init__(self, parent: VFS, mount: str, child: VFS, child_path: str):
        self.parent = parent
        self.mount = mount
        self.child = child
        self.child_path = child_path

    def _get_vfs_path(self, path: str) -> Tuple[VFS, str]:
        path = os.path.normpath(path)
        if Path(path).is_relative_to(self.mount):
            return self.child, os.path.join(self.child_path, os.path.relpath(path, self.mount))
        return self.parent, path

    async def read(self, path: str) -> bytes:
        vfs_counter.add(1, {"type": "mount", "op": "read"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.read(path)

    async def write(self, path: str, data: bytes) -> None:
        vfs_counter.add(1, {"type": "mount", "op": "write"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.write(path, data)

    async def is_file(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "mount", "op": "is_file"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.is_file(path)

    async def is_exe(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "mount", "op": "is_exe"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.is_exe(path)

    async def is_dir(self, path: str) -> bool:
        vfs_counter.add(1, {"type": "mount", "op": "is_dir"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.is_dir(path)

    async def mode(self, path: str) -> Optional[int]:
        vfs_counter.add(1, {"type": "mount", "op": "mode"})
        vfs, path = self._get_vfs_path(path)
        return await vfs.mode(path)

    async def hash(self) -> bytes:
        vfs_counter.add(1, {"type": "mount", "op": "hash"})
        parent_hash = await self.parent.hash()
        child_hash = await self.child.hash()
        return sha256(b"||".join([
            parent_hash, self.mount.encode(), child_hash, self.child_path.encode()
        ])).digest()

    async def layers(self) -> tuple[Layer, ...]:
        vfs_counter.add(1, {"type": "mount", "op": "layers"})
        res = await self.parent.layers()
        res += (
            CommandLayer(".", ".", ("rm", "-rf", self.mount)),
            CommandLayer(".", ".", ("mkdir", self.mount))
        )
        res += tuple(
            replace(l, path=os.path.join(self.mount, l.path), extract_under=self.child_path)
            for l in await self.child.layers()
        )
        return res
