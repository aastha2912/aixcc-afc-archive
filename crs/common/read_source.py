"""
Simple helper for reading source code.
Used for reading inside or outside of Docker, so broken
out for convenience
"""
from crs.common.types import Result, Ok, Err, CRSError, SourceContents
from crs.common.utils import requireable, require
from crs.common.vfs import VFS

MAX_SUGGEST = 10

@requireable
async def check_file(vfs: VFS, path: str) -> Result[None]:
    """
    Returns None on success.

    If the basename of the path exists elsewhere in the root_dir,
    some (at most 10) will be given in the error message.
    """
    if await vfs.is_dir(path):
        return Err(CRSError(f"{path} is a directory"))
    tree = require(await vfs.tree())
    return tree.check_path(path)

async def check_file_type(data: bytes) -> Result[None]:
    try:
        header = data[:4]
        if header.startswith(b"\x7fELF"):
            return Err(CRSError("that is a compiled ELF file, we cannot read it"))
        elif header.startswith(b"PK") and header[2] < 10:
            return Err(CRSError("that may be a compiled .jar file, we cannot read it"))
        elif header.startswith(b"\xca\xfe\xba\xbe"):
            return Err(CRSError("that is a compiled .class file, we cannot read it"))
    except FileNotFoundError:
        return Err(CRSError("the file could not be found"))
    return Ok(None)

def annotate_lines(lines: list[str], start: int) -> list[str]:
    end = start + len(lines)
    return [f"{i:>{len(str(end))}d} {line}" for i, line in enumerate(lines, start=start)]

@requireable
async def read_source(vfs: VFS, path: str, line_number: int, display_lines: bool = False, context_lines: int=100) -> Result[SourceContents]:
    a = max(1, line_number + 1 - context_lines)
    b = a + context_lines * 2
    return await read_source_range(vfs, path, a, b, display_lines=display_lines)

@requireable
async def read_source_range(vfs: VFS, path: str, start: int, end: int, display_lines: bool = False) -> Result[SourceContents]:
    if not 1 <= start < end:
        return Err(CRSError(f"invalid line numbers: ({start}, {end})"))

    require(await check_file(vfs, path))

    try:
        data = await vfs.read(path)
        require(await check_file_type(data))
        text = data.decode(errors="replace")
        lines = ("\n"+text).splitlines() # add a newline in front because line numbers are 1-indexed
        if start > len(lines):
            return Err(CRSError(f"line number out of range (only {len(lines)} lines)"))
        out_lines = annotate_lines(lines[start:end], start) if display_lines else lines[start:end]
        contents = "\n".join(out_lines)
        return Ok(SourceContents(contents=contents, line_start=start, line_end=min(end, len(lines))))
    except FileNotFoundError:
        return Err(CRSError("the file could not be found"))
