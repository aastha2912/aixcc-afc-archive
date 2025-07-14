from asyncio.subprocess import PIPE
from typing import Literal, Optional
import asyncio
import os
import re

from crs_rust import logger
import numpy

import crs_rust
from crs_rust import Edit
from crs.common.types import Ok, Err, Result, CRSError
from crs.common.utils import requireable, require
from crs.common.vfs import VFS, EditableOverlayFS
from crs.common import aio, process

HUNK_HEADER_RE = re.compile(r"\A@@\s-(\d*),\d*\s\+\d*,\d*\s@@")
NEW_SENTINEL = "+~NEW~+"
GAP_CHAR = "+~GAP~+"

def is_file_header(line: str) -> bool:
    return line.startswith("--- ") or line.startswith("+++ ")

def is_hunk_header(line: str) -> bool:
    return HUNK_HEADER_RE.match(line) is not None

def is_header_line(line: str) -> bool:
    return is_hunk_header(line) or is_file_header(line)

def is_context_line(line: str) -> bool:
    return line.startswith(" ")

def is_edit_line(line: str) -> bool:
    return (line.startswith("+") or line.startswith("-")) and not is_file_header(line)

def cleanup_patch_line(line: str) -> str:
    if is_header_line(line):
        return line
    if is_context_line(line) or is_edit_line(line):
        return line
    # LLM sometimes omits leading space on context lines
    # Note whitespace differences will be ignored
    return " " + line

def remove_extra_whitespace(patch: str) -> str:
    # LLMs sometimes output extra spaces before the edit markers
    # try to detect that and delete it
    lines = patch.splitlines()
    # remove any unneeded header lines at the top of the file
    try:
        start_line = list(map(is_hunk_header, lines)).index(True) + 1
    except ValueError:
        start_line = 0
    editlines = lines[start_line:]
    # if only a header is given
    if not editlines:
        return patch

    shortest = min([len(l) for l in editlines])
    for c in range(shortest, 0, -1):
        if all(l.startswith(" "*c) for l in editlines):
            break
    else:
        return patch

    return "\n".join(lines[:start_line] + [l[c:] for l in editlines])

async def cleanup_patch(patch: str) -> Result[str]:
    lines = patch.splitlines()

    # remove any unneeded header lines at the top of the file
    start_line = list(map(is_hunk_header, lines)).index(True)
    lines = lines[start_line:]

    lines = [cleanup_patch_line(l) for l in lines]
    # cleanup each line
    patch = "\n".join(lines)

    # use rediff to fixup hunk headers
    async with process.run("rediff", "-", stdin=PIPE, stdout=PIPE) as proc:
        stdout, _ = await proc.communicate(patch.encode())
        if await proc.wait() != 0:
            return Err(CRSError("rediff failed"))
        return Ok(stdout.decode(errors='replace'))

# some small routines of this is modified from
# https://github.com/stanfordnlp/string2string/blob/main/string2string/alignment/classical.py

class SWMatcher:
    def __init__(self) -> None:
        self.scorer = MatchScorer()

    def get_alignment(self, seq1: list[str], seq2: list[str]):
        n = len(seq1)
        m = len(seq2)
        mat = numpy.zeros((n+1, m+1))

        for i in range(1, n+1):
            for j in range(1, m+1):
                score = max(
                    mat[i-1, j-1] + self.scorer(seq1[i-1], seq2[j-1]),
                    mat[i-1, j] + self.scorer(seq1[i-1], GAP_CHAR),
                    mat[i, j-1] + self.scorer(seq2[j-1], GAP_CHAR),
                    0,
                )
                mat[i, j] = score

        return mat

    def backtrack(
        self,
        score_matrix: numpy.ndarray[tuple[int, int], numpy.dtype[numpy.float64]],
        seq1: list[str],
        seq2: list[str]
    ) -> tuple[list[Optional[int]], list[Optional[int]]]:
        # Initialize the aligned substrings.
        aligned_idx1: list[Optional[int]] = []
        aligned_idx2: list[Optional[int]] = []

        # Get the position with the maximum score in the score matrix.
        i, j = numpy.unravel_index(numpy.argmax(score_matrix, axis=None), score_matrix.shape)

        # Backtrack the score matrix.
        while score_matrix[i, j] != 0:
            # Get the scores of the three possible paths.
            match_score = score_matrix[i - 1, j - 1] + self.scorer(seq1[i - 1], seq2[j - 1])
            delete_score = score_matrix[i - 1, j] + self.scorer(seq1[i - 1], GAP_CHAR)
            insert_score = score_matrix[i, j - 1] + self.scorer(seq2[j - 1], GAP_CHAR)

            # Get the maximum score.
            max_score = max(match_score, delete_score, insert_score)

            # Backtrack the score matrix.
            if max_score == match_score:
                i -= 1
                j -= 1
                aligned_idx1.append(int(i))
                aligned_idx2.append(int(j))
            elif max_score == delete_score:
                i -= 1
                aligned_idx1.append(int(i))
                aligned_idx2.append(None)
            elif max_score == insert_score:
                j -= 1
                aligned_idx1.append(None)
                aligned_idx2.append(int(j))

        #print(aligned_idx1[::-1], aligned_idx2[::-1])
        #print('\n'.join(seq1[i] for i in aligned_idx1[::-1] if i is not None))
        #print("="*10)
        #print('\n'.join(seq2[i] for i in aligned_idx2[::-1] if i is not None))
        # Return the aligned substrings.
        return aligned_idx1[::-1], aligned_idx2[::-1]

class MatchScorer:
    def __init__(self) -> None:
        self.delete_weight = 1
        self.match_weight = 0
        self.sub_weight = 1.5
        self.max_distance = 5
        self.alignment_mismatch = -0.5

    def char_score(self, a:str, b:str):
        if a == b:
            return self.match_weight
        # lower penalty for mismatched numbers for things like timestamps in logs
        if a.isdigit() and b.isdigit():
            return self.sub_weight/10
        # lower penalty for simple case mismatch
        if a.lower() == b.lower():
            return self.sub_weight/10
        return self.sub_weight

    def __call__(self, a: str, b: str) -> float:
        """
        Return a similarity score based on edit distance
        """
        if a == b:
            if len(a) == 0: return 1
            return len(a).bit_length()**0.5

        if NEW_SENTINEL in (a, b) and GAP_CHAR in (a, b):
            return 0.01
        if "" in (a, b) and GAP_CHAR in (a, b):
            return -0.01

        cutoff = min(len(a), len(b), self.max_distance)
        # shortcut handle very different lens
        if abs(len(a) - len(b)) > cutoff:
            return self.alignment_mismatch
        # shortcut handle the case with long common prefix
        i = 0
        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                break
        a = a[i:]
        b = b[i:]

        # do the edit distance thing
        n = len(a)
        m = len(b)
        dist = numpy.zeros((n+1, m+1))
        for i in range(1, n+1):
            dist[i, 0] = self.delete_weight * i
        for j in range(1, m+1):
            dist[0, j] = self.delete_weight * j

        for i in range(1, n+1):
            early_exit = True
            for j in range(1, m+1):
                score = max(
                    dist[i-1, j-1] + self.char_score(a[i-1], b[j-1]),
                    dist[i-1, j] + self.delete_weight,
                    dist[i, j-1] + self.delete_weight,
                )
                dist[i, j] = score
                if score < cutoff:
                    early_exit = False
            if early_exit:
                return self.alignment_mismatch
        return (min(len(a), len(b))).bit_length()**0.5 * (1-dist[n,m]/self.max_distance)**2

def norm_whitespace(seq: list[str]):
    return [' '.join(s.split()) for s in seq]

def find_alignment(seq1: list[str], seq2: list[str], est_line: Optional[int]=None) -> Result[list[tuple[Optional[int],Optional[int]]]]:
    """
    Finds the alignment between seq1 and seq2, returning the indexes inside of seq1
    where they match. You probably want +1 to the last index to use it for slicing stuff

    Returns
    -------
    tuple or None
        start and end index (or None for errors)
    dict or None
        dict describing any errors (or None for no errors)
    """
    seq1 = norm_whitespace(seq1)
    seq2 = norm_whitespace(seq2)
    # TODO: might be nice to be able to use affine gap penalties
    n = SWMatcher()
    mat = n.get_alignment(seq1, seq2)
    topscore = mat.max()
    winners = numpy.count_nonzero(mat.flatten() == topscore)
    # print(winners, topscore, numpy.argmax(mat, axis=0))
    if winners != 1:
        if topscore < 2:
            return Err(CRSError("no good matches found"))
        guesses = 0
        if est_line is not None:
            est_sites = numpy.where(mat == topscore)[0]
            for est_site in est_sites:
                if abs((est_line - len(seq2)/2) - est_site) < 10:
                    logger.warning(f"ambiguous patch, relying on line numbers to pick lines at {est_site}")
                    guesses += 1
                else:
                    # wipe top scores from other lines for backtracking
                    mat[est_site] = 0
        if guesses != 1:
            return Err(CRSError(
                "Context lines did not match OR matched multiple locations. "
                "Please double-check the correctness of the context lines "
                "and/or provide additional context lines."
            ))

    path0, path1 = n.backtrack(mat, seq1, seq2)
    return Ok(list(zip(path0, path1)))

def check_fuzzy_match(orig_line: Optional[str], new_line: Optional[str]) -> Result[None]:
    if new_line == NEW_SENTINEL:
        return Ok(None)
    orig_l = orig_line.strip() if orig_line else ""
    new_l = new_line.strip() if new_line else ""
    other = {"{":"}", "}":"{", "(":")", ")": "("}
    for char in "}{)(":
        orig_count = orig_l.count(char)
        new_count = new_l.count(char)
        change = "inserted" if new_count > orig_count else "removed"
        if orig_count != new_count:
            if orig_line is not None and new_line is not None:
                return Err(CRSError(
                    (
                        "The patch context lines have introduced a typographic error. The context you "
                        f"provided {change} `{char}`. Please double check the source code and ensure you "
                        "did not get mixed up about the semantic meaning! If you wish to continue with "
                        "your change, ensure you use the correct original source lines for context.\n"
                        "This may also happen if the fuzzy matching around your patch fails due to "
                        "inconsistencies (such as extra/missing newlines)."
                    ),
                    extra={
                        "original_line": orig_l,
                        "provided_line": new_l,
                    }
                ))
            elif orig_line is None:
                if new_l.count(other[char]) == new_count:
                    continue
                return Err(CRSError(
                    (
                        "The patch context lines have introduced a typographic error. The context you "
                        f"provided {change} `{char}` when no such line existed in the original file. "
                        "Please double check the source code and ensure you "
                        "did not get mixed up about the semantic meaning! If you wish to continue with "
                        "your change, ensure you use the correct original source lines for context.\n"
                        "This may also happen if the fuzzy matching around your patch fails due to "
                        "inconsistencies (such as extra/missing newlines)."
                    ),
                    extra={"implicitly_inserted_line": new_l}
                ))
            elif new_line is None:
                if orig_l.count(other[char]) == orig_count:
                    continue
                return Err(CRSError(
                    (
                        "The patch context lines have introduced a typographic error. The context you "
                        f"provided {change} `{char}` and you did not provide any lines which matched "
                        "to it. Please double check the source code and ensure you "
                        "did not get mixed up about the semantic meaning! If you wish to continue with "
                        "your change, ensure you use the correct original source lines for context.\n"
                        "This may also happen if the fuzzy matching around your patch fails due to "
                        "inconsistencies (such as extra/missing newlines)."
                    ),
                    extra={"implicitly_deleted_line": orig_l}
                ))
    return Ok(None)


EditType = Literal['+', '-', '']

class Hunk:
    def __init__(self, relpath: str, elines: list[tuple[EditType, str]], line_number: int):
        self.relpath = relpath
        self.elines = elines
        self.line_number = line_number

async def apply_as_edit(vfs: VFS, relpath: str, new_content: bytes) -> crs_rust.Edit:
    old_content = await vfs.read(relpath)
    await vfs.write(relpath, new_content)
    return await asyncio.to_thread(crs_rust.compute_edit, relpath, old_content, new_content)

@requireable
async def apply_hunk(vfs: VFS, hunk: Hunk) -> Result[Edit]:
    orig_bytes = await vfs.read(hunk.relpath)

    hunk_lines = [l if t != '+' else NEW_SENTINEL for t,l in hunk.elines]
    orig_lines = orig_bytes.decode(errors="replace").splitlines()
    if len(orig_lines) == 0:
        arange = [(None, i) for i in range(len(hunk_lines))]
    else:
        try:
            hunk_bytes = "\n".join(hunk_lines).encode()
            arange = await asyncio.to_thread(crs_rust.sw_align, orig_bytes, hunk_bytes, hunk.line_number)
        except Exception as e:
            return Err(CRSError(f"sw_align failed: {e}"))
    # first sanity check our alignment: if we have typographic issues we expect to be relevant
    # (such as missing/inserted braces or parens, we should error out)
    for orig_idx, hunk_idx in arange:
        require(check_fuzzy_match(
            orig_lines[orig_idx] if orig_idx is not None else None,
            hunk_lines[hunk_idx] if hunk_idx is not None else None,
        ))

    # start with the original file up to where we first started matching
    orig_lines_bytes = orig_bytes.splitlines(keepends=True)
    new_lines = orig_lines_bytes[0:arange[0][0]]
    last_orig_line = -1
    for orig_line, patch_line in arange:
        if orig_line is not None: # we have an orig line, use that
            last_orig_line = orig_line
            # (unless we are meant to delete it)
            if patch_line is not None and hunk.elines[patch_line][0] == '-':
                continue
            new_lines.append(orig_lines_bytes[orig_line]) # otherwise add it
        elif patch_line is not None:
            new_lines.append(hunk.elines[patch_line][1].encode()+b"\n")
    if last_orig_line == -1 and len(orig_lines) > 0:
        return Err(CRSError('no good match found, please add more context lines'))
    new_lines += orig_lines_bytes[last_orig_line+1:]
    new_content = b"".join(new_lines)
    edit = await apply_as_edit(vfs, hunk.relpath, new_content)
    return Ok(edit)

def parse_hunks(relpath: str, patch: str) -> list[Hunk]:
    # split up each hunk and apply separately
    hunks: list[Hunk] = []
    this_hunk = None
    for line in patch.splitlines():
        if is_file_header(line):
            continue
        if match := HUNK_HEADER_RE.match(line):
            if this_hunk:
                hunks.append(this_hunk)
            line_no = int(match.groups()[0])
            this_hunk = Hunk(relpath, [], line_no)
        elif this_hunk is not None:
            edit_type = '+' if line.startswith("+") else ('-' if line.startswith("-") else "")
            this_hunk.elines.append( (edit_type, line[1:]) )
    if this_hunk:
        hunks.append(this_hunk)
    return hunks

@requireable
async def virtual_diff(path: str, a: bytes, b: bytes) -> Result[str]:
    async with aio.tmpfile() as tf:
        _ = await tf.path.write_bytes(a)
        cmd = [
            "diff", "-u",
            "--label", f"a/{path}", tf.name,
            "--label", f"b/{path}", "-",
        ]
        async with process.run(*cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
            stdout, stderr = await proc.communicate(b)
            if await proc.wait() > 1:
                return Err(CRSError(f"diff command error. stderr: {stderr}, stdout: {stdout}"))
            return Ok(stdout.decode(errors="replace"))

@requireable
async def fuzzy_patch(vfs: VFS, relpath: str, patch: str) -> Result[tuple[str, list[Edit]]]:
    relpath = os.path.normpath(relpath)
    patch = require(await cleanup_patch(patch))
    hunks = parse_hunks(relpath, patch)

    patch_vfs = EditableOverlayFS(vfs)
    edits: list[Edit] = []
    for i, hunk in enumerate(hunks):
        match await apply_hunk(patch_vfs, hunk):
            case Ok(edit): edits.append(edit)
            case Err(err):
                return Err(CRSError(
                    f"Error in hunk index {i} (line {hunk.line_number}): {err.error}", extra=err.extra
                ))

    assert list(patch_vfs.files.keys()) == [relpath]

    # convert all changed files into a unified diff
    patch_chunks: list[str] = []
    for path, file in patch_vfs.files.items():
        ref = await vfs.read(path)
        vdiff = require(await virtual_diff(path, ref, file.contents))
        patch_chunks.append(vdiff)
        # write the patched file back to vfs
        await vfs.write(path, file.contents)

    diff_patch = "\n".join(patch_chunks)
    return Ok((diff_patch, edits))
