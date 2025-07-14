from functools import wraps
from typing import Callable, Concatenate, NotRequired, Optional, TypedDict
import os

from crs.common.read_source import check_file
from crs.common.types import Coro, Ok, Err, Result, CRSError
from crs.common.utils import requireable, require

from crs.common.fuzzy_patch import (
    Edit,
    fuzzy_patch, apply_as_edit, virtual_diff,
    cleanup_patch, remove_extra_whitespace,
    is_hunk_header, is_edit_line,
)

from crs.common.vfs import EditableOverlayFS

class Editor:
    # one patch with multiple hunks may do several edits
    Patch = TypedDict('Patch', {'edits': list[Edit], 'path': str, 'patch': str, 'desc': NotRequired[str]})

    vfs: EditableOverlayFS
    patches: list['Editor.Patch']

    def __init__(self, vfs: EditableOverlayFS, patches: Optional[list['Editor.Patch']] = None):
        self.vfs = vfs
        self.patches = patches or []

    async def get_repo_diff(self, repo: str) -> str:
        """
        Return a unified diff of all changes that have been applied to the `repo`.
        `repo` must be a relative path to git repository contained in `self.base_dir`.
        """
        repo = os.path.normpath(repo)
        vfs = self.vfs
        parent_vfs = vfs.parent
        chunks: list[str] = []
        for path in vfs.files.keys():
            if not path.startswith(f"{repo}/"):
                continue
            a = await parent_vfs.read(path)
            b = await vfs.read(path)
            diff_chunk = (await virtual_diff(os.path.relpath(path, repo), a, b)).expect("diff failed")
            chunks.append(diff_chunk)
        return "".join(chunks)

    def fixup_line(self, path: str, line: int, is_start: bool = False) -> int:
        for patch in self.patches:
            if not os.path.normpath(patch["path"]) == os.path.normpath(path):
                continue
            for edit in patch["edits"]:
                line_start, line_end = edit.lines
                _, old_line_end = edit.old_lines
                delta = line_end - old_line_end
                if line > line_end:
                    # if line is after the hunk, no change
                    line += delta
                elif line < line_start:
                    # if line before the hunk, no change
                    pass
                elif is_start:
                    # if line is in the hunk but we want to round down
                    line = line_start
                else:
                    # if line is in the hunk but we want to round up
                    line = line_end
        return line

    # TODO: populate a patch here
    async def write_tracked(self, relpath: str, new_content: bytes):
        edit = await apply_as_edit(self.vfs, relpath, new_content)
        self.patches.append({"edits": [edit], "path": relpath, "patch": ""})

    @requireable
    async def apply(self, relpath: str, patch: str) -> Result[None]:
        require(await check_file(self.vfs, relpath))
        _, edits = require(await fuzzy_patch(self.vfs, relpath, patch))
        self.patches.append({"edits": edits, "path": relpath, "patch": patch})
        return Ok(None)

    @property
    def patch_num(self) -> int:
        return len(self.patches)

    async def rewind_to(self, patch_num: int) -> None:
        for patch in reversed(self.patches[patch_num:]):
            for edit in reversed(patch["edits"]):
                path = edit.file
                new_lines = (await self.vfs.read(path)).splitlines(keepends=True)
                await self.vfs.write(path, b''.join(
                    new_lines[:edit.lines[0]] +
                    edit.before +
                    new_lines[edit.lines[1]:]
                ))
        self.patches = self.patches[:patch_num]

    @staticmethod
    def requires_file[**P, T](
        fn: Callable[Concatenate['Editor', P], Coro[Result[T]]]
    ) -> Callable[Concatenate['Editor', P], Coro[Result[T]]]:
        @wraps(fn)
        async def wrapped(self: 'Editor', /, *args: P.args, **kwargs: P.kwargs) -> Result[T]:
            file_path: Optional[object] = kwargs.get("file_path")
            if isinstance(file_path, str):
                if not await self.vfs.is_file(file_path):
                    return Err(CRSError("file not found"))
            return await fn(self, *args, **kwargs)
        return wrapped

    TotalEdits = TypedDict('TotalEdits', {'total_edits': int})
    async def undo_last_patch(self) -> Result[TotalEdits]:
        if self.patch_num == 0:
            return Err(CRSError("no edits remain to undo"))
        await self.rewind_to(-1)
        return Ok(Editor.TotalEdits(total_edits=self.patch_num))

    EditsList = TypedDict('EditsList', {'edits': list[str]})
    async def list_edits(self) -> Result[EditsList]:
        if self.patch_num == 0:
            return Err(CRSError("no edits remain"))
        return Ok(Editor.EditsList(edits=[p['patch'] for p in self.patches]))

    MatchingLines = TypedDict('MatchingLines', {'matching_lines': list[int]})

    class Note(TypedDict):
        note: str

    @requireable
    async def apply_patch(self, path: str, patch: str) -> Result[Note]:
        ERROR_NOTE = (
            "this patch was not applied and does not need to be undone\n"
            f"there are still {self.patch_num} patches currently applied"
        )

        patch = remove_extra_whitespace(patch)
        lines = patch.splitlines()
        hunks = list(map(is_hunk_header, lines)).count(True)
        if hunks == 0:
            return Err(CRSError(
                (
                    "Invalid patch format. Make sure it includes the hunk headers "
                    "with approximate line numbers, i.e. `@@ -l,s +l,s @@`"
                ),
                extra={"note": ERROR_NOTE},
            ))
        edits = list(map(is_edit_line, lines)).count(True)
        if edits == 0:
            return Err(CRSError(
                (
                    "Patch contains no changes. Make sure it is in patch format, "
                    "with + indicating added lines and - indicating removed lines."
                ),
                extra={"note": ERROR_NOTE}
            ))
        patch = require(await cleanup_patch(patch))
        match await self.apply(path, patch):
            case Ok(): pass
            case Err(e):
                extra = {"note": ERROR_NOTE}
                if e.extra:
                    extra.update(e.extra)
                return Err(CRSError(f"patch did NOT apply successfully: {e.error}", extra=extra))

        return Ok(Editor.Note(note=
            f"appended to the current list of patches (now have {self.patch_num} patches)\n"
            "you may want to check that the change compiles successfully before continuing!"
        ))

    @requireable
    async def rewrite_lines(self, path: str, start: int, end: int, new: list[str]) -> Result[Note]:
        """
        Generates and applies a patch which rewrites the lines [{start}, {end}) in {path} with
        the lines in {new}. The original lines will be removed and replaces with the lines in
        {new}. The lines in {new} should not contain a "\\n" character.

        Parameters
        ----------
        path : str
            The path to the file to patch.
        start : int
            The first line in the file to rewrite
        end : int
            The first line after the region to rewrite
        new: list[str]
            The list of new lines. These should not include "\\n" characters.

        Returns
        -------
        dict
            contains a success message if successful, otherwise contains an error message
        """
        require(await check_file(self.vfs, path))
        if end < start:
            return Err(CRSError("end < start"))
        orig_bytes = await self.vfs.read(path)
        lines = orig_bytes.splitlines(keepends=True)
        if start > len(lines):
            return Err(CRSError("start > len(lines)"))
        new_lines = lines[:start] + [l.encode("utf-8")+b"\n" for l in new] + lines[end:]
        new_bytes = b"".join(new_lines)
        patch = require(await virtual_diff(path, orig_bytes, new_bytes))
        return await self.apply_patch(path, patch)
