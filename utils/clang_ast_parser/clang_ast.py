import json
import os
import re
import subprocess
import sys

from bisect import bisect
from itertools import accumulate
from multiprocessing import Pool
from pathlib import Path
import tempfile
from typing import Any, Optional, TypedDict

# ignore things starting with '<' those are
# special clang things like <scratch space>
file_regex = re.compile(rb'"file": "([^<].*)"')

class CompileCommand(TypedDict):
    directory: str
    arguments: list[str]
    file: str

class DefSite(TypedDict):
    name: str
    mangled_name: str
    begin: int
    end: int
    qual_type: str

def line_for(offset_line_dat: list[int], line_info: dict[str, Any]) -> Optional[int]:
    if (line := line_info.get("line")) is not None:
        return line
    elif (offset := line_info.get("offset")) is not None:
        return bisect(offset_line_dat, offset)
    elif (expand := line_info.get("expansionLoc")) is not None:
        if expand.get("includedFrom"):
            return None
        return line_for(offset_line_dat, expand)
    return None

def parse_range(offset_line_dat: list[int], ast: dict[str, Any]) -> Optional[tuple[int, int]]:
    range_dat = ast.get('range', {})
    begin = None
    end = None
    if range_dat:
        if (begin_info := range_dat.get('begin')):
            if 'includedFrom' in begin_info:
                return
            begin = line_for(offset_line_dat, begin_info)
        if begin is None:
            return
        if (end_info := range_dat.get('end')):
            if 'includedFrom' in end_info:
                return
            end = line_for(offset_line_dat, end_info)
    if end is None or begin is None:
        return
    return begin, end

def get_func(offset_line_dat: list[int], ast: dict[str, Any]) -> Optional[DefSite]:
    if any(x.get('kind') == 'CompoundStmt' for x in ast.get('inner', [])):
        return get_defsite(offset_line_dat, ast)

def get_defsite(offset_line_dat: list[int], ast: dict[str, Any]) -> Optional[DefSite]:
    match parse_range(offset_line_dat, ast):
        case begin, end:
            pass
        case None:
            return

    name = ast.get('name')
    if name is None:
        return

    return DefSite(
        name = name,
        mangled_name = ast.get('mangledName', name),
        begin = begin,
        end = end,
        qual_type = ast.get('type', {}).get('qualType')
    )

def get_funcs_rec(offset_line_dat: list[int], ast: dict[str, Any], toplevel: bool = False) -> list[DefSite]:
    match ast.get('kind'):
        case 'FunctionDecl':
            func_defined = get_func(offset_line_dat, ast)
            if func_defined:
                return [func_defined]
        case 'VarDecl':
            if ast.get("storageClass") != "extern":
                var_defined = get_defsite(offset_line_dat, ast)
                if var_defined:
                    return [var_defined]
        case 'TranslationUnitDecl':
            start: list[DefSite]=[]
            return sum([get_funcs_rec(offset_line_dat, nested, toplevel=True) for nested in ast.get('inner', [])], start=start)
        case 'CXXRecordDecl':
            # not really a DefSite, but let's act like it is to simplify C stuff
            start: list[DefSite]=[]
            if ast.get("completeDefinition", False):
                match parse_range(offset_line_dat, ast):
                    case begin, end:
                        name = ast.get("name")
                        if name:
                            start: list[DefSite]=[DefSite(
                                name = name,
                                mangled_name = ast.get("mangledName", name),
                                begin = begin,
                                end = end,
                                qual_type="class"
                            )]
                    case None:
                        pass
            return sum([get_funcs_rec(offset_line_dat, nested) for nested in ast.get('inner', [])], start=start)
        case 'CXXMethodDecl':
            func_defined = get_func(offset_line_dat, ast)
            if func_defined:
                return [func_defined]
        case _:
            return []
    return []

def handle_subfile(cwd: Path, src_path: Path, json_path: Path) -> tuple[Path, list[DefSite], set[Path]]:
    try:
        offset_line_dat = list(accumulate([0] + [len(x) for x in src_path.open(mode="rb").readlines()]))
    except OSError:
        return (src_path, [], set())

    if json_path.stat().st_size == 0:
        return (src_path, [], set())

    files_referenced = set(cwd / Path(p.decode(errors="replace")) for p in file_regex.findall(json_path.read_bytes()))
    try:
        parsed = json.load(json_path.open(mode="rb"))
    except json.JSONDecodeError:
        _ = sys.stderr.write(f"failed to load {src_path}'s json: {json_path} [{json_path.open(mode='rb').read(64)!r}\n")
        _ = sys.stderr.flush()
        return (src_path, [], set())

    return (src_path, get_funcs_rec(offset_line_dat, parsed), files_referenced)

def run_one_compile_command(c: CompileCommand) -> Optional[tuple[Path, list[DefSite], set[Path]]]:
    _ = sys.stderr.write(Path(c['directory'], c['file']).as_posix() + "\n")
    _ = sys.stderr.flush()
    with tempfile.NamedTemporaryFile() as tf:
        try:
            retcode = subprocess.call([c['arguments'][0], "-Xclang", "-ast-dump=json", "-fsyntax-only", *c['arguments'][1:]], cwd=c['directory'], stdout=tf.file)
            if retcode != 0:
                return None
        except OSError as e:
            # if the cwd doesn't exist, this might happen
            _ = sys.stderr.write(f"failed to run clang: {e}")
            return None

        return handle_subfile(Path(c['directory']), Path(c['directory'], c['file']).resolve(), Path(tf.name))

def parse_clang_ast(compile_commands_path: Path, includeable_paths: list[str]):
    compile_commands = json.load(compile_commands_path.open("rb"))
    with Pool(8) as pool:
        parsed_res = pool.map(
            run_one_compile_command,
            [
                c for c in compile_commands
                # note that includeable_paths MIGHT be a file path, that's "fine"
                # is_relative_to is string based, so it will allow that literal path
                if len(includeable_paths) == 0 or any(
                    Path(c['directory'], c['file']).is_relative_to(inc) for inc in includeable_paths
                )
        ])

    paths_referenced: set[Path] = set()
    for s in parsed_res:
        if s:
            paths_referenced |= s[2]

    paths_referenced = set(p.relative_to("/src") if p.is_relative_to("/src") else p for p in paths_referenced)
    files_referenced = set(os.path.normpath(p.as_posix()) for p in paths_referenced)
    return {s[0].relative_to("/src").as_posix():s[1] for s in parsed_res if s}, list(files_referenced)

if __name__ == "__main__":
    json.dump(parse_clang_ast(Path(sys.argv[1]), sys.argv[2:]), sys.stdout)
