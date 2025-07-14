import asyncio
import os
from asyncio.subprocess import PIPE
from typing import Callable, Iterable, List

from crs import config
from crs.common import docker
from crs.common.aio import Path
from crs.common.alru import alru_cache
from crs.common.types import CRSError, Err, Ok, Result
from crs.common.utils import requireable, only_ok
from crs.modules.python_sandbox import SANDBOX_IMAGE_NAME

from crs_rust import PathSuffixTree as _PathSuffixTree

PATH_SUFFIX_TREE_TIMEOUT = 3600

class PathSuffixTree:
    """Thin Python wrapper around the Rust suffix-tree implementation."""

    __slots__ = ("_tree", "_raw_json")

    def __init__(self, raw_json: bytes):
        # Keep a frozen copy for re-dumping later
        self._raw_json: bytes = bytes(raw_json)
        # Pass straight to Rust
        self._tree = _PathSuffixTree(raw_json)

    @alru_cache(maxsize=2048, filter=only_ok)
    @staticmethod
    async def from_layers(
        layers: Iterable[docker.Layer],
    ) -> Result["PathSuffixTree"]:
        mounts = {config.PATH_SUFFIX_TREE: "/opt/path_suffix_tree.py"}
        try:
            async with docker.run(
                SANDBOX_IMAGE_NAME,
                group=docker.DockerGroup.Misc,
                mounts=mounts,
                timeout=PATH_SUFFIX_TREE_TIMEOUT,
            ) as run:
                # Copy layers into the sandbox
                match await docker.vwrite_layers(run, "/vfs", layers):
                    case Ok():
                        pass
                    case Err() as err:
                        return err
                proc = await run.exec("/opt/path_suffix_tree.py", "/vfs", stdout=PIPE)
                stdout, _ = await proc.communicate()
                return Ok(PathSuffixTree(stdout))  # stdout is already bytes
        except TimeoutError:
            return Err(CRSError("building suffix tree timed out"))

    @alru_cache(maxsize=2048)
    @staticmethod
    async def from_path(path: Path) -> "PathSuffixTree":
        raw = await path.read_bytes()
        return await asyncio.to_thread(PathSuffixTree, raw)

    async def dump_to_path(self, path: Path):
        _ = await path.write_bytes(self._raw_json)

    def _wrap_rust_call[R](self, fn: Callable[[str], R], s: str) -> Result[R]:
        s = os.path.normpath(s)
        try:
            return Ok(fn(s))
        except CRSError as e:
            return Err(e)

    @requireable
    def normalize_path(self, p: Path | str) -> Result[str]:
        """Return the unique suffix for *p*."""
        return self._wrap_rust_call(self._tree.normalize_path, str(p))

    @requireable
    def check_path(self, p: Path | str) -> Result[None]:
        """Ensure *p* exists and is unambiguous."""
        return self._wrap_rust_call(self._tree.check_path, str(p))

    def get_full_paths(self, partial: Path | str) -> Result[List[str]]:
        return self._wrap_rust_call(self._tree.get_full_paths, str(partial))

    def all_paths(self) -> list[str]:
        return self._tree.all_paths()
