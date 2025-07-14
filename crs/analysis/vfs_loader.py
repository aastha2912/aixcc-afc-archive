import asyncio
from crs.common.aio import Path
from crs.common.vfs import VFS
from crs.common.types import Result, Ok
from crs.common.utils import require, requireable

from .data import AnalysisProject, SourceFile
from . import c_tree_sitter, java_tree_sitter

@requireable
async def load_vfs(vfs: VFS, src_path: Path, language: str | None = None) -> Result[AnalysisProject]:
    match language:
        case "c" | "c++":
            language_exts = (".c",)
        case "jvm":
            language_exts = (".java",)
        case _:
            language_exts = (".c", ".java")

    project = AnalysisProject()
    src_path_str = src_path.as_posix()
    for path in require(await vfs.tree()).all_paths():
        if not path.startswith(src_path_str):
            continue
        if not path.endswith(language_exts):
            continue
        if "/test" in path:
            continue

        source = await vfs.read(path)

        strpath = path
        sf = SourceFile(strpath, source)
        project.files[strpath] = sf

        if path.endswith(".c"):
            project.decls += await asyncio.to_thread(c_tree_sitter.parse, sf)
        elif path.endswith(".java"):
            project.decls += await asyncio.to_thread(java_tree_sitter.parse, sf)

    return Ok(project)
