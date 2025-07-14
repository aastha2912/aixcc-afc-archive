from asyncio.subprocess import PIPE
from collections import defaultdict
from crs.common.aio import Path
from typing import Iterable, cast, Any, Callable, Optional, TypedDict, TYPE_CHECKING, AsyncIterator, Mapping

import aiosqlite
import asyncio
import contextlib
import orjson
import os

from crs_rust import logger
import tree_sitter
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_java

from crs import config
from crs.app.app_meta import cur_task_exit_stack
from crs.common import aio, docker, joern
from crs.common.alru import async_once, alru_cache
from crs.common.read_source import read_source, read_source_range
from crs.common.sqlite import SQLiteDB
from crs.modules.python_sandbox import SANDBOX_IMAGE_NAME
from crs.common.types import (
    Ok, Err, Result, Coro, CallDef, DefinitionType, DefinitionSite, LineDefinition, CRSError,
    FileDefinition, FileDefinitions, FileReferences, FileReference, SourceDefSite, SourceContents
)
from crs.common.utils import only_ok, requireable, require, scoped_pipe, trim_tool_output
from crs.common.vfs import VFS
if TYPE_CHECKING:
    from crs.modules.project import Project
    from crs.modules.source_editor import Editor


MAX_SUGGEST = 5
CLANG_AST_CACHE_VERSION = 6
GTAGS_INIT_TIMEOUT = 3600
RIPGREP_TIMEOUT = 180
MAX_SEARCH_RESULTS = 50

CLANG_AST_PARSER = config.CRSROOT / ".." / "utils" / "clang_ast_parser" / "clang_ast.py"
JOERN_FUNC_LOOKUP = config.CRSROOT / ".." / "utils" / "joern" / "make_func_lookup.scala"

ts_java_language = tree_sitter.Language(tree_sitter_java.language())
ts_c_language = tree_sitter.Language(tree_sitter_c.language())
ts_cpp_language = tree_sitter.Language(tree_sitter_cpp.language())

ts_java_query = ts_java_language.query("""
(method_declaration) @def
(class_declaration) @def
(interface_declaration) @def
""")

ts_c_query = ts_c_language.query("""
(function_definition) @def
(preproc_def) @def
(struct_specifier) @def
""")

ts_cpp_query = ts_cpp_language.query("""
(function_definition) @def
(preproc_def) @def
(struct_specifier) @def
""")

ts_java_parser = tree_sitter.Parser(ts_java_language)
ts_c_parser = tree_sitter.Parser(ts_c_language)
ts_cpp_parser = tree_sitter.Parser(ts_cpp_language)

class ClangSearcher:
    def __init__(self, proj: "Project", vfs: Callable[[], Coro[VFS]]):
        self.proj = proj
        self.building_lock = asyncio.Lock()
        self.vfs = vfs

    @alru_cache(filter=only_ok)
    @requireable
    async def defn_lookup(self) -> Result[dict[str, list[DefinitionSite]]]:
        clang_def_sites, _ = require(await self.get_clang_def_sites())
        def build():
            lookup: dict[str, list[DefinitionSite]] = {}
            for path, defns in clang_def_sites.items():
                for defn in defns:
                    if defn.name not in lookup:
                        lookup[defn.name] = []
                    lookup[defn.name].append( DefinitionSite(file=path, start=defn.begin, end=defn.end) )
            return lookup
        return Ok(await asyncio.to_thread(build))

    @requireable
    async def is_file_in_cu(self, p: Path) -> Result[bool]:
        clang_def_sites, _ = require(await self.get_clang_def_sites())
        return Ok(p in clang_def_sites)

    @requireable
    async def is_file_referenced(self, p: Path) -> Result[bool]:
        clang_def_sites, headers = require(await self.get_clang_def_sites())
        return Ok(p in clang_def_sites or p in headers)

    @requireable
    async def case_insensitive_defn_lookup(self) -> Result[dict[str, list[DefinitionSite]]]:
        lookup = require(await self.defn_lookup())
        return Ok({k.lower(): v for k, v in lookup.items()})

    @requireable
    async def find_defs(self, name: str) -> Result[list[DefinitionSite]]:
        lookup = require(await self.defn_lookup())
        return Ok(lookup.get(name, []))

    @requireable
    async def find_lines(self, name: str, ignore: Optional[dict[Path, list[int]]] = None, case_insensitive: bool = False) -> Result[dict[Path, list[DefinitionSite]]]:
        ignore = ignore or {}

        if case_insensitive:
            symbol_lookup = require(await self.case_insensitive_defn_lookup())
        else:
            symbol_lookup = require(await self.defn_lookup())

        res: dict[Path, list[DefinitionSite]] = {}

        for site in symbol_lookup.get(name, []):
            path = Path(site["file"])
            if not any(site["start"] <= line <= site["end"] for line in ignore.get(path, [])):
                res[path] = res.get(path, [])
                res[path].append(site)

        return Ok(res)

    @requireable
    async def find_file_defs(self, path: Path) -> Result[list[LineDefinition]]:
        clang_def_sites, _ = require(await self.get_clang_def_sites())
        if path not in clang_def_sites:
            return Err(CRSError(f"no clang-ast results for {path}"))
        return Ok([LineDefinition(name=x.name, line=x.begin) for x in clang_def_sites[path]])

    @requireable
    async def find_func_for_line(self, path: Path, line: int) -> Result[tuple[str, int]]:
        clang_def_sites, _ = require(await self.get_clang_def_sites())
        for x in clang_def_sites.get(path, []):
            if x.begin <= line <= x.end:
                return Ok((x.name, x.begin))
        return Err(CRSError(f"no func found for {path}:{line}"))

    async def _clang_def_cache_file(self):
        vfs = await self.vfs()
        hash = await vfs.hash()
        return (self.proj.data_dir / f"parsed_clang_ast_{hash.hex()}.json")

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def get_clang_def_sites(self) -> Result[tuple[dict[Path, list[SourceDefSite]], set[Path]]]:
        def from_raw(defns: dict[str, Any], referenced_files: list[str]):
            return (
                {Path(k):[SourceDefSite(**x) for x in v] for k,v in defns.items()},
                set(Path(f) for f in referenced_files)
            )

        cache_path = await self._clang_def_cache_file()
        if await cache_path.exists():
            try:
                # use a basic version string to invalidate old results if we update this
                data = await cache_path.read_bytes()
                version, defns, referenced_files = await asyncio.to_thread(orjson.loads, data)
                if version == CLANG_AST_CACHE_VERSION:
                    return Ok(from_raw(defns, referenced_files))
            except ValueError:
                pass

        includeable_paths: set[str] = {require(await self.proj.get_working_dir())}
        for harness in require(await self.proj.init_harness_info()):
            # harness.source is relative to /src, so we always have parts[0]
            # if the fuzzer is /src/fuzzer.c that will get included by this as well
            includeable_paths.add(Path("/src", Path(harness.source).parts[0]).as_posix())


        try:
            async with self.proj.run_bear_docker(mounts={CLANG_AST_PARSER: "/opt/clang_ast.py"}) as wrun:
                run = require(wrun)

                proc = await run.exec(
                    "python3", "/opt/clang_ast.py", "/src/compile_commands.json", *includeable_paths,
                    stdout=PIPE, stderr=PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    return Err(CRSError(f"failed to run bear inst commands! {stderr!r}"))

                defns, referenced_files = await asyncio.to_thread(orjson.loads, stdout)

                # update the cache
                data = await asyncio.to_thread(orjson.dumps, [CLANG_AST_CACHE_VERSION, defns, referenced_files])
                _ = await cache_path.write_bytes(data)

                return Ok(from_raw(defns, referenced_files))
        except TimeoutError:
            return Err(CRSError("clang_ast docker timed out"))

MAX_DECL_LENGTH = 200
class JoernSearcher:
    def __init__(self, project: "Project", vfs: Callable[[], Coro[VFS]]) -> None:
        self.project = project
        self.vfs = vfs

    async def _joern_def_cache_file(self):
        vfs = await self.vfs()
        hash = await vfs.hash()
        return (self.project.data_dir / f"joern_defs_{hash.hex()}_v1.json")

    @requireable
    async def _get_defs(self) -> Result[bytes]:
        cache_path = await self._joern_def_cache_file()
        if await cache_path.exists():
            return Ok(await cache_path.read_bytes())
        query = await Path(JOERN_FUNC_LOOKUP).read_text()
        res = require(await joern.run_query(self.project, query)).encode()
        cache_file = await self._joern_def_cache_file()
        async with aio.tmpfile(dir=cache_file.parent) as tf:
            _ = await tf.path.write_bytes(res)
            await tf.path.replace(cache_file)
        return Ok(res)

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def _indexed_joern_defs(self) -> Result[dict[str, list[DefinitionSite]]]:
        data = require(await self._get_defs())
        def index():
            parsed = orjson.loads(data)
            result = defaultdict[str, list[DefinitionSite]](list)
            for func in parsed['funcs']:
                not_required = {"code": code[:MAX_DECL_LENGTH]} if (code := func.get('code')) else {}
                result[func['name']].append(
                    DefinitionSite(
                        file=Path(func['source']),
                        start=func['start_line'],
                        end=func['end_line'],
                        **not_required
                    )
                )
            for typedef in parsed['types']:
                result[typedef['name']].append(
                    DefinitionSite(
                        file=Path(typedef['source']),
                        start=typedef['start_line'],
                        end=-1,
                    )
                )
            return result
        return Ok(await asyncio.to_thread(index))

    @requireable
    async def find_lines(self, name: str) -> Result[dict[Path, list[DefinitionSite]]]:
        defns = require(await self._indexed_joern_defs()).get(name, [])
        result = defaultdict[Path, list[DefinitionSite]](list)
        for defn in defns:
            result[defn["file"]].append(defn)
        return Ok(result)

class SourceDocker:
    def __init__(self, vfs: VFS, mounts: Mapping[Path, str | Path] = {}):
        self.vfs = vfs
        self.mounts = mounts
        self._pinned_run: Optional[docker.DockerRun] = None

    @contextlib.asynccontextmanager
    async def _new_run(self):
        async with docker.run(SANDBOX_IMAGE_NAME, mounts=self.mounts, timeout=None, group=docker.DockerGroup.Misc, cores=0) as run:
            (await docker.vwrite_layers(run, "/src", await self.vfs.layers())).expect("SourceDocker failed to write /src")
            yield run

    @contextlib.asynccontextmanager
    async def _new_pinned_run(self):
        async with self._new_run() as run:
            # if self._pinned_run is None, set it and yield
            # otherwise exit this run scope and yield the _pinned_run
            if self._pinned_run is None:
                self._pinned_run = run
                try:
                    yield run
                    return
                finally:
                    self._pinned_run = None
        yield self._pinned_run

    @contextlib.asynccontextmanager
    async def run(self, timeout: Optional[float] = None):
        async with asyncio.timeout(timeout):
            if self._pinned_run:
                yield self._pinned_run
                return
            if stack := cur_task_exit_stack():
                run = await stack.enter_async_context(self._new_pinned_run())
                yield run
                return
            async with self._new_run() as run:
                yield run

class GTagDB:
    CRS_GTAGS_CONF = config.CRSROOT / "gtags.conf"

    def __init__(self, proj: "Project", vfs: Callable[[], Coro[VFS]], pre_vfs: Callable[[], Coro[VFS]]) -> None:
        self.vfs = vfs
        self.pre_vfs = pre_vfs
        self.project = proj
        language = proj.info.language
        if language in {"c", "c++"}:
            self.clang_searcher: Optional[ClangSearcher] = ClangSearcher(proj, self.vfs)
            self.joern_searcher = None
        elif language == "jvm":
            self.clang_searcher = None
            self.joern_searcher: Optional[JoernSearcher] = JoernSearcher(proj, self.vfs)
        else:
            self.clang_searcher = None
            self.joern_searcher = None
        self.source_docker = SourceDocker(self.project.vfs.parent, mounts={self.CRS_GTAGS_CONF: "/etc/gtags.conf"})

    @async_once
    async def gtags_dir(self: 'GTagDB') -> Path:
        res = self.project.data_dir / f"gtags_{await self.project.parent_edit_state()}"
        if await res.exists():
            return res

        async with self.source_docker.run(timeout=GTAGS_INIT_TIMEOUT) as run:
            if await (await run.exec("mkdir", "-p", "/tmp/gtags")).wait() != 0:
                raise RuntimeError("gtags generation mkdir failed")

            proc = await run.exec(
                "gtags", "--gtagsconf", "/etc/gtags.conf", "--skip-unreadable",
                "--sqlite", "-C", "/src", "/tmp/gtags",
            )
            if await proc.wait() != 0:
                raise RuntimeError("gtags generation failed")

            async with aio.tmpdir(dir=self.project.data_dir) as td:
                with scoped_pipe() as (pipe_read, pipe_write):
                    write_tar = await run.exec("tar", "cf", "-", "-C", "/tmp/gtags", ".", stdout=pipe_write)
                    read_tar  = await run.scope.exec("tar", "xf", "-", "-C", td.as_posix(), stdin=pipe_read)

                if any(await asyncio.gather(write_tar.wait(), read_tar.wait())):
                    raise RuntimeError(f"gtags transfer failed write={write_tar.returncode} read={read_tar.returncode}")

                try:
                    _ = await td.rename(res)
                except OSError:
                    if not await res.exists(): # noqa: ASYNC120 # this doesn't really matter if the task is cancelled
                        raise
                    # res exists, so was likely a race and should be fine to continue

        return res

    @async_once
    async def rtags_db(self) -> SQLiteDB:
        db_path = (await self.gtags_dir()) / "GRTAGS"
        return await SQLiteDB.open_pinned(db_path, ro=True)

    @async_once
    async def tags_db(self) -> SQLiteDB:
        db_path = (await self.gtags_dir()) / "GTAGS"
        return await SQLiteDB.open_pinned(db_path, ro=True)

    @async_once
    async def path_db(self) -> SQLiteDB:
        db_path = (await self.gtags_dir()) / "GPATH"
        return await SQLiteDB.open_pinned(db_path, ro=True)

    @contextlib.asynccontextmanager
    async def rtagsdb_conn(self) -> AsyncIterator[aiosqlite.Connection]:
        db = await self.rtags_db()
        async with db.sqlite_connect() as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def tagsdb_conn(self):
        db = await self.tags_db()
        async with db.sqlite_connect() as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def pathdb_conn(self):
        db = await self.path_db()
        async with db.sqlite_connect() as conn:
            yield conn

    async def _get_path(self, id: int) -> Optional[str]:
        async with self.pathdb_conn() as conn:
            async with conn.execute("select dat from db where key=?", [id]) as cursor:
                row = await cursor.fetchone()
                if row is None:
                    return None
                return cast(str, row[0])

    @alru_cache(maxsize=256)
    async def cached_query_res(self, path: str):
        vfs = await self.vfs()
        queries: list[tuple[tree_sitter.Parser, tree_sitter.Query]] = []
        match Path(path).suffix.lower():
            case ".java":
                queries.append((ts_java_parser, ts_java_query))
            case _:
                # run with C and C++ because of bugs...
                queries.append((ts_c_parser, ts_c_query))
                queries.append((ts_cpp_parser, ts_cpp_query))
        src = await vfs.read(path)
        def query_one(parser: tree_sitter.Parser, query: tree_sitter.Query):
            tree = parser.parse(src)
            return query.matches(tree.root_node)
        return await asyncio.gather(*(asyncio.to_thread(query_one, parser, query) for parser, query in queries))

    @alru_cache(maxsize=16384)
    async def get_symbol_extent(self, path: str, line_start: int) -> Optional[tuple[int, int]]:
        enclosing_match = None
        smallest = float('inf')
        # find the tightest match among the candidates
        for query in await self.cached_query_res(path):
            for _, match_def in query:
                site = match_def['def'][0]
                start, end = site.start_point.row, site.end_point.row
                # slightly mismatch from tree sitter to our internal line numbers
                start += 1
                end += 1
                if start <= line_start and end >= line_start:
                    if end - start < smallest:
                        enclosing_match = (start, end)
                        smallest = end - start

        return enclosing_match

    async def _content(self, path: str, line: int) -> str:
        res = await read_source_range(await self.vfs(), path, line, line + 1)
        match res:
            case Ok(r): return r["contents"]
            case Err(err): return f"ERROR reading contents: {err.error}"

    async def _typed_def(self, path: str, line: int, type: DefinitionType, include_content: bool = False) -> FileDefinition:
        return FileDefinition(
            line=line,
            content=await self._content(path, line) if include_content else None,
            type=type
        )

    def _row_type(self, loc_desc: str) -> DefinitionType:
        if "#@d" in loc_desc:
            return "#define"
        if "@t" in loc_desc:
            return "typedef"
        if "@n(" in loc_desc:
            return "function"
        if loc_desc.count("@") == 1:
            return "reference"
        return "unknown"


    async def find_partial(
        self,
        db: aiosqlite.Connection,
        symbol: str,
        case_insensitive: bool = False,
    ) -> list[tuple[str, str]]:
        extra = " COLLATE nocase" if case_insensitive else ""
        res: set[tuple[str, str]] = set()
        async with db.execute(f"select key, dat, extra from db where key LIKE (?) {extra}", [f"%{symbol}%"]) as cursor:
            async for sym, loc_desc, file_id in cursor:
                if ' @n ' not in loc_desc:
                    continue # we only handle the format with @n
                fname = await self._get_path(file_id)
                if fname is None:
                    continue
                res.add( (fname, sym) )
        return list(res)

    async def find_lines(
        self,
        db: aiosqlite.Connection,
        symbol: str,
        case_insensitive: bool = False,
        partial: bool = False,
        max: Optional[int] = None,
        include_content: bool = False
    ) -> dict[str, list[FileDefinition]]:
        found: dict[str, list[FileDefinition]] = {}
        extra = " COLLATE nocase" if case_insensitive else ""
        eq = "="
        if partial:
            eq = "LIKE"
            symbol = f"%{symbol}%"
        async with db.execute(f"select dat, extra from db where key {eq} (?) {extra}", [symbol]) as cursor:
            async for loc_desc, file_id in cursor:
                if ' @n ' not in loc_desc:
                    continue # we only handle the format with @n
                fname = await self._get_path(file_id)
                if fname is None:
                    continue
                fname = os.path.normpath(fname)
                found[fname] = found.get(fname, [])
                # line looks like '{file_no} @n {first_line}[-{following_lines}][,{next_line}[-{following_lines}]*
                # as an example: 7 @n 42-1,16-1,20
                # this means line 42,43,59,60,80
                line_info = loc_desc.split(" @n ")[1].split()[0]
                line_deltas = line_info.split(",")
                current = 0
                row_type = self._row_type(loc_desc)
                for delta in line_deltas:
                    offset, *more = delta.split("-")
                    current = current + int(offset)
                    found[fname].append(await self._typed_def(fname, current, row_type, include_content=include_content))
                    if more:
                        for _ in range(int(more[0])):
                            current += 1
                            found[fname].append(await self._typed_def(fname, current, row_type, include_content=include_content))
                    if max is not None and len(found) >= max:
                        return found
        return found

    @alru_cache(maxsize=1024)
    async def find_refs(
        self, symbol: str, case_insensitive: bool = False, max: Optional[int] = None, include_content: bool = False
    ) -> Result[dict[str, list[FileDefinition]]]:
        async with self.rtagsdb_conn() as db:
            return Ok(await self.find_lines(db, symbol, case_insensitive=case_insensitive, max=max, include_content=include_content))

    async def find_defs(
        self, symbol: str, case_insensitive: bool = False, max: Optional[int] = None, include_content: bool = False
    ) -> Result[dict[str, list[FileDefinition]]]:

        async with self.tagsdb_conn() as db:
            found: dict[str, list[FileDefinition]] = await self.find_lines(db, symbol, case_insensitive=case_insensitive, max=max, include_content=include_content)

        if self.clang_searcher:
            lines_covered = {Path(k):[i.line for i in v] for k,v in found.items()}
            match await self.clang_searcher.find_lines(symbol, ignore=lines_covered, case_insensitive=case_insensitive):
                case Ok(matches):
                    for path, deflist in matches.items():
                        for defn in deflist:
                            found[path.as_posix()] = found.get(path.as_posix(), [])
                            found[path.as_posix()].append(await self._typed_def(path.as_posix(), defn['start'], "function", include_content=include_content))
                case _:
                    pass
        return Ok(found)

    CallSites = TypedDict('CallSites', {'caller': str, 'file': str, 'line': int})
    @alru_cache(maxsize=1024)
    @requireable
    async def find_callers(self, symbol: str, case_insensitive: bool = False, max: Optional[int] = None, include_content: bool = False) -> Result[list[CallSites]]:
        frefs = require(await self.find_refs(symbol, case_insensitive=case_insensitive, max=max, include_content=include_content))
        callers: list[GTagDB.CallSites] = []
        for file, refs in frefs.items():
            for ref in refs:
                match await self.find_func_for_line(file, ref.line):
                    case Ok((func, line)): pass
                    case Err(): continue
                if func:
                    callers.append({'caller': func, 'file': file, 'line': line})
        return Ok(callers)

    @requireable
    async def find_callers_with_defs(self, callee: str, case_insensitive: bool = False, include_content: bool = False) -> Result[list[CallDef]]:
        """
        Search for all callers of a function, method, macro, etc in the repository.
        Returns a dictionary of calling methods and the locations of where those
        callers are defined.
        <example_output>
        [{"caller":[{"file_name":"src/foo/bar.c", "lines":[123]}]}]
        </example_output>
        <warning>
        searches for the function name only. For functions defined as part of a class
        such as FooClass.BarFunction, search only for BarFunction
        </warning>

        Parameters
        ----------
        name : str
            The name of the function to find callers of
        case_insensitive : bool
            If true, searches without regards to the case

        Returns
        -------
        list[dict]
            a list of each possible caller, eg [{"caller":[{"file_name":"src/foo/bar.c", "lines":[123]}]}]
        """

        callers = require(await self.find_callers(callee, case_insensitive=case_insensitive, max=100, include_content=include_content))
        if callers:
            return Ok([
                CallDef(
                    caller=c['caller'],
                    file=c['file'],
                    line=c['line'],
                    content=await self._content(c['file'], c['line'])
                ) for c in callers
            ])
        if "." in callee:
            return Err(CRSError(
                "no results found. If you are searching for a function defined in a class, "
                "please provide ONLY the function name."
            ))
        return Err(CRSError("no results found"))

    async def get_fid_for_path(self, fpath: str) -> Result[Any]:
        fpath = "./" + (fpath.lstrip(".").lstrip("/"))
        async with self.pathdb_conn() as db:
            async with db.execute("select key from db where dat=?", [fpath]) as cursor:
                row = await cursor.fetchone()
                if row is None:
                    return Err(CRSError("file path not found"))
                return Ok(row[0])

    @alru_cache(maxsize=1024)
    @requireable
    async def find_func_for_line(self, fpath: str, line: int) -> Result[tuple[str, int]]:
        # return the "closest previous" function
        # this works except for things inside the global body
        fid = require(await self.get_fid_for_path(fpath))
        # we have the file, now look at all func definitions in that file
        async with self.tagsdb_conn() as db:
            async with db.execute("select key, dat from db where extra=?", [fid]) as cursor:
                func = None
                best_line = 0
                async for fn_name, loc_desc in cursor:
                    if "@n" not in loc_desc:
                        continue # we can't parse this
                    if "@t" in loc_desc:
                        continue # this is just a typedef declaration
                    line_num = int(loc_desc.split()[2])
                    if line_num <= line and line_num > best_line:
                        func = fn_name
                        best_line = line_num

        if func and self.clang_searcher and (await self.clang_searcher.find_func_for_line(Path(fpath), best_line)).is_ok():
            return Ok((func, best_line))
        if func and await self.get_symbol_extent(fpath, best_line):
            return Ok((func, best_line))
        return Err(CRSError("no corresponding function found"))

    async def list_defs_in_file(self, fpath: str) -> list[LineDefinition]:
        results: list[LineDefinition] = []
        clang_findings: dict[str, list[int]] = defaultdict(list)
        if self.clang_searcher:
            match await self.clang_searcher.find_file_defs(Path(fpath)):
                case Ok(defs):
                    results.extend(defs)
                    for entry in defs:
                        clang_findings[entry.name].append(entry.line)
                case _:
                    pass

        match await self.get_fid_for_path(fpath):
            case Err(): return []
            case Ok(fid): pass
        async with self.tagsdb_conn() as db:
            async with db.execute("select key, dat from db where extra=?", [fid]) as cursor:
                async for fn_name, loc_desc in cursor:
                    if "@n" not in loc_desc:
                        continue # we can't parse this
                    line_num = int(loc_desc.split()[2])
                    func = fn_name
                    # only add it if it doesn't overlap with something from clang
                    if not any([abs(clang_line - line_num) < 2 for clang_line in clang_findings.get(func, [])]):
                        results.append(LineDefinition(name=func, line=line_num))
            return results

    async def _clang_definition_line_range(self, name: str, fpath: str | Path | None = None, line_number: Optional[int] = None) -> Optional[Result[DefinitionSite]]:
        if self.clang_searcher is None:
            return None
        if fpath:
            if not (await self.clang_searcher.is_file_in_cu(Path(fpath))).unwrap_or(False):
                return None
        match await self.clang_searcher.find_lines(name):
            case Err(): return None
            case Ok(defsites): pass
        return await self._postprocess_definition_line_range(name, fpath, line_number, defsites)

    async def _joern_definition_line_range(self, name: str, path: str | Path | None = None, line_number: Optional[int] = None) -> Optional[Result[DefinitionSite]]:
        if self.joern_searcher is None:
            return None
        match await self.joern_searcher.find_lines(name):
            case Err(): return None
            case Ok(defsites): pass
        return await self._postprocess_definition_line_range(name, path, line_number, defsites)

    async def _postprocess_definition_line_range(self, name: str, fpath: str | Path | None, line_number: Optional[int], defsites: dict[Path, list[DefinitionSite]]) -> Result[DefinitionSite]:
        # our map has entries for all parsed files, even if no definitions were found
        defsites = {k:v for k,v in defsites.items() if v}

        async def filter_pre_build(defns: dict[Path, list[DefinitionSite]]):
            return {path:sites for path, sites in defns.items() if await (await self.pre_vfs()).is_file(path.as_posix())}

        if not fpath and len(defsites) > 1:
            if len(filtered := await filter_pre_build(defsites)) == 1:
                defsites = filtered
            else:
                if len(filtered) > 1:
                    defsites = filtered
                error = "Must provide path because we found definitions in multiple files, including: "
                error += ", ".join([defsite.as_posix() for defsite in defsites][:MAX_SUGGEST])
                if len(defsites) > MAX_SUGGEST:
                    error += f", and {len(defsites) - MAX_SUGGEST} other files"
                return Err(CRSError(error))

        for defpath, deflist in defsites.items():
            if fpath is not None and defpath != Path(fpath):
                continue
            deflist.sort(key=lambda defn: defn["start"])
            number_width = len(str(deflist[-1]["start"]))
            candidates: list[str] = []
            for defn in deflist:
                number = defn["start"]
                code = defn.get("code")
                if not code:
                    code = await self._content(str(defn["file"]), number)
                candidates.append(f"{number:>{number_width}d} {code}")
            if line_number is not None:
                deflist = list(defn for defn in deflist if defn["start"] == line_number)
                if not deflist:
                    error = "Definition not found at the line number, but we found definitions in the file:\n"
                    error += "\n".join(candidates)
                    return Err(CRSError(error))
            if len(deflist) > 1:
                error = "Must provide line number because there are multiple definitions in the file:\n"
                error += "\n".join(candidates)
                return Err(CRSError(error))
            defn = deflist[0]
            if defn["end"] == -1:
                extent = await self.get_symbol_extent(str(defn["file"]), defn["start"])
                if extent:
                    _, end = extent
                    defn["end"] = end
            return Ok(defn)
        error = "Definition not found"
        if len(defsites) > 0:
            error += ". But we found definitions in other files, including: "
            error += ", ".join([defsite.as_posix() for defsite in defsites][:MAX_SUGGEST])
            if len(defsites) > MAX_SUGGEST:
                error += f", and {len(defsites) - MAX_SUGGEST} other files"
        elif "." in name:
            return Err(CRSError(
                "Definition not found. If you are searching for a symbol defined in a class or struct, please provide ONLY the symbol name."
            ))
        return Err(CRSError(error))

    async def definition_line_range(self, name: str, fpath: str | Path | None = None, line_number: Optional[int] = None) -> Result[DefinitionSite]:
        if res := await self._clang_definition_line_range(name, fpath, line_number):
            return res
        if res := await self._joern_definition_line_range(name, fpath, line_number):
            return res
        async with self.tagsdb_conn() as db:
            matches = await self.find_lines(db, name)
        files = list(matches.keys())
        if not fpath and len(matches) > 1:
            error = "Must provide path because we found definitions in multiple files, including: "
            error += ", ".join(files[:MAX_SUGGEST])
            if len(files) > MAX_SUGGEST:
                error += f", and {len(files) - MAX_SUGGEST} other files"
            return Err(CRSError(error))

        for fname, deflist in matches.items():
            if fpath is not None and Path(fname) != Path(fpath):
                continue
            deflist.sort(key=lambda defn: defn.line)
            number_width = len(str(deflist[-1].line))
            candidates: list[str] = []
            for defn in deflist:
                number = defn.line
                line = await self._content(fname, number)
                candidates.append(f"{number:>{number_width}d} {line}")
            if line_number is not None:
                deflist = list(defn for defn in deflist if defn.line == line_number)
                if not deflist:
                    error = "Definition not found at the line number, but we found definitions in the file:\n"
                    error += "\n".join(candidates)
                    return Err(CRSError(error))
            if len(deflist) > 1:
                error = "Must provide line number because there are multiple definitions in the file:\n"
                error += "\n".join(candidates)
                return Err(CRSError(error))
            for defn in deflist:
                extent = await self.get_symbol_extent(fname, defn.line)
                if extent is None:
                    continue
                return Ok(DefinitionSite(
                    file=Path(fname),
                    start=extent[0],
                    end=extent[1]
                ))
            return Err(CRSError(f"could not find extent for {name} in {fname}"))

        error = "Definition not found"
        if len(files) > 0:
            error += ". But we found definitions in other files, including: "
            error += ", ".join(files[:MAX_SUGGEST])
            if len(files) > MAX_SUGGEST:
                error += f", and {len(files) - MAX_SUGGEST} other files"
        return Err(CRSError(error))

    async def find_all_funcs(self, dirprefixes: Optional[Iterable[str]] = None) -> set[str]:
        async with self.tagsdb_conn() as db:
            async with db.execute("SELECT key, extra FROM db WHERE dat LIKE '%@n(%'") as cursor:
                funcs = await cursor.fetchall()
                # if we don't care about where the funcs come from, we're done
                if dirprefixes is None:
                    return {r[0] for r in funcs}

            where = " OR ".join("(key LIKE (?))" for _ in dirprefixes)
            async with self.pathdb_conn() as db:
                async with db.execute(f"SELECT dat FROM db WHERE {where}", [f"{prefix}%" for prefix in dirprefixes]) as cursor:
                    fids = {r[0] for r in await cursor.fetchall()}
                    return {r[0] for r in funcs if r[1] in fids}

class FunctionWithPath(TypedDict):
    name: str
    path: str

class Searcher:
    def __init__(self, project: "Project", editor: "Editor", gtags: Optional[GTagDB] = None):
        self.project = project
        self.editor = editor
        self.gtags = gtags or GTagDB(project, self.vfs, self.pre_vfs)
        self.source_docker = self.gtags.source_docker

    async def vfs(self) -> VFS:
        if await self.project.build_bear_tar() is None:
            return self.project.vfs.parent # use the unedited vfs
        return await self.project.get_bear_vfs()

    async def pre_vfs(self) -> VFS:
        return self.project.vfs.parent

    async def source_vfs(self, path: str):
        # use the edited vfs if the file exists there, otherwise use the indexed vfs
        vfs = self.project.vfs
        if not await vfs.is_file(path):
            vfs = await self.vfs()
        return vfs

    async def read_full_source(self, file_name: str) -> Result[str]:
        """
        Read the full source code file located at {file_name}.
        Not intended to be used by agents

        Parameters
        ----------
        file_name : str
            The relative path of the source file, eg 'src/foo/bar.c'

        Returns
        -------
        dict
            dict with src info, lines used, and any errors
        """
        vfs = await self.source_vfs(file_name)
        if not await vfs.is_file(file_name):
            return Err(CRSError("file does not exist"))
        return Ok((await vfs.read(file_name)).decode(errors='replace'))

    async def read_source_range(self, file_name: str, start: int, end: int, display_lines: bool = True) -> Result[SourceContents]:
        """
        Read the given source range from the file located at {file_name}.
        Not intended to be used by agents
        """
        vfs = await self.source_vfs(file_name)
        if not await vfs.is_file(file_name):
            return Err(CRSError("file does not exist"))
        return await read_source_range(vfs, file_name, start, end, display_lines=display_lines)

    async def read_source(self, file_name: str, line_number: int) -> Result[SourceContents]:
        return await read_source(await self.source_vfs(file_name), file_name, line_number, display_lines=True)

    async def enforce_relative(self, fname: str) -> str:
        vfs = await self.vfs()
        if await vfs.is_file(fname):
            return fname
        # TODO: #return Path(fname).relative_to(self.folder).as_posix()
        logger.warning(f"how to make relative? {fname}")
        return fname

    @requireable
    async def find_definition(self, name: str, path: Optional[str] = None, case_insensitive: bool = False) -> Result[list[FileDefinitions]]:
        all_defs = require(await self.gtags.find_defs(name, case_insensitive=case_insensitive, max=MAX_SEARCH_RESULTS+1, include_content=True))
        res = [
            FileDefinitions(file_name=await self.enforce_relative(fname), defs=defs) for fname, defs in all_defs.items()
        ]
        pre_filter = res
        if path:
            res = [
                defn for defn in res if Path(os.path.normpath(defn.file_name)).is_relative_to(os.path.normpath(path))
            ]

        # check if we can reduce this by dropping files that are only in the post-build vfs
        pre_sites = [s for s in res if await (await self.pre_vfs()).is_file(s.file_name)]
        if len(pre_sites) > 0:
            res = pre_sites

        if len(res) > MAX_SEARCH_RESULTS:
            return Err(CRSError(
                f"Found too many(more than {MAX_SEARCH_RESULTS}) definitions of that symbol. " +
                ("Please reconsider your approach." if path else
                "Please include a path to limit results or consider another approach.")
            ))
        if res:
            return Ok(res)

        if pre_filter:
            return Err(CRSError(
                "no results found in specified path, but there are results in other paths: " +
                ", ".join(set(s.file_name for s in pre_filter))
            ))

        if "." in name:
            return Err(CRSError(
                "no results found. If you are searching for a function defined in a class, "
                "please provide ONLY the function name."
            ))
        return Err(CRSError("no results found"))

    async def enclosing_definition(self, file_name: str, line_number: int) -> Result[tuple[str, int]]:
        return await self.gtags.find_func_for_line(file_name, line_number)

    @requireable
    async def ripgrep(self, string: str, path: Optional[str] = None, case_insensitive: bool=False, max: int = MAX_SEARCH_RESULTS) -> Result[list[FileReferences]]:
        try:
            async with self.source_docker.run(timeout=RIPGREP_TIMEOUT) as run:
                path = os.path.join("/src", path) if path else "/src"
                extra_args: list[str] = [arg for ftype in ["java", "c", "cpp"] for arg in ["-t", ftype]]
                if case_insensitive:
                    extra_args.append("-i")
                async with run.exec_scoped(
                    "rg", "-m", str(max), "--json", *extra_args, "-F", "-e", string, path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ) as process:
                    stdout, stderr = await process.communicate()
                    if process.returncode not in (0, 1):  # 0 means matches found, 1 means no matches
                        err = trim_tool_output(stderr).decode(errors="replace")
                        return Err(CRSError(f"Ripgrep failed with error: {err}"))
                def parse_output(max: int):
                    results: defaultdict[str, list[FileReference]] = defaultdict(list)
                    count = 0
                    for line in stdout.splitlines():
                        if b"\"type\":\"match\"" not in line:
                            continue
                        data = orjson.loads(line)["data"]
                        path = data["path"]["text"]
                        content = data["lines"]["text"].rstrip()
                        line = data["line_number"]
                        results[path].append(FileReference(line=line, content=content, enclosing_definition="N/A"))
                        count += 1
                        if count > max:
                            break
                    return [FileReferences(file_name=path, refs=refs) for path, refs in results.items()]
                return Ok(await asyncio.to_thread(parse_output, max))
        except TimeoutError:
            return Err(CRSError("ripgrep timed out"))

    @requireable
    async def find_references(self, name: str, path: Optional[str] = None, case_insensitive: bool=False) -> Result[list[FileReferences]]:
        Sites = TypedDict('Sites', {"file_name": str, "refs": list[FileDefinition]})
        file_refs = require(await self.gtags.find_refs(name, case_insensitive=case_insensitive, max=51, include_content=True))
        if len(file_refs) == 0:
            logger.warning("refs were empty, falling back to defs just in case")
            file_refs = require(await self.gtags.find_defs(name, case_insensitive=case_insensitive, max=51, include_content=True))
        sites: list[Sites] = [
            {"file_name":await self.enforce_relative(fname), "refs":refs}
            for fname,refs in file_refs.items()
            if path or (await self.compiler_might_use_path(fname))
        ]
        pre_filter = sites
        if path:
            sites = [s for s in sites if Path(os.path.normpath(s["file_name"])).is_relative_to(os.path.normpath(path))]

        # check if we can reduce this by dropping files that are only in the post-build vfs
        pre_sites = [s for s in sites if await (await self.pre_vfs()).is_file(s["file_name"])]
        if len(pre_sites) > 0:
            sites = pre_sites

        if len(sites) > MAX_SEARCH_RESULTS:
            return Err(CRSError(
                f"Found too many(more than {MAX_SEARCH_RESULTS}) references to that symbol. " +
                ("Please reconsider your approach." if path else
                "Please include a path to limit results or consider another approach.")
            ))

        res = [
            FileReferences(
                file_name=file["file_name"],
                refs=[
                    FileReference(
                        enclosing_definition=enc_def.unwrap()[0],
                        line=ref.line,
                        content=ref.content
                    )
                    for ref in file["refs"]
                    if (enc_def := await self.enclosing_definition(file["file_name"], ref.line)).is_ok()
                ]
            )
            for file in sites
        ]

        if res:
            return Ok(res)

        if pre_filter:
            return Err(CRSError(
                "no results found in specified path, but there are results in other paths: " +
                ", ".join(set(s["file_name"] for s in pre_filter))
            ))

        # try falling back to ripgrep
        match await self.ripgrep(name, path=path, case_insensitive=case_insensitive, max=51):
            case Ok(res) if len(res) > 0:
                if sum(len(file_res.refs) for file_res in res) > MAX_SEARCH_RESULTS:
                    return Err(CRSError(
                        f"Found too many(more than {MAX_SEARCH_RESULTS}) references to that string. " +
                        ("Please reconsider your approach." if path else
                        "Please include a path to limit results or consider another approach.")
                    ))
                return Ok(res)
            case _:
                pass

        if "." in name:
            return Err(CRSError(
                "no results found. If you are searching for a symbol defined in a class or "
                "struct, please provide ONLY the symbol name."
            ))
        return Err(CRSError("no results found"))

    async def list_definitions(self, path: str) -> Result[list[LineDefinition]]:
        res = await self.gtags.list_defs_in_file(path)
        if len(res) > 200:
            return Err(CRSError(
                "Found several (more than 200) definitions in that file. Please reconsider "
                "your approach as this is too many results to handle efficiently."
            ))
        if res:
            return Ok(res)
        return Err(CRSError("no results found"))

    class FileSourceContents(SourceContents):
        file: str

    @requireable
    async def read_definition(self, name: str, path: Optional[str] = None, line_number: Optional[int] = None, display_lines: bool = True) -> Result[FileSourceContents]:
        defres = require(await self.gtags.definition_line_range(name, path, line_number))
        file = defres["file"].as_posix()
        res = require(await read_source_range(
            await self.source_vfs(file),
            file,
            self.editor.fixup_line(file, defres["start"], is_start=True),
            self.editor.fixup_line(file, defres["end"]+1, is_start=False),
            display_lines=display_lines
        ))
        return Ok(Searcher.FileSourceContents(**res, file=file))

    async def compiler_might_use_path(self, p: str | Path) -> bool:
        if self.gtags.clang_searcher:
            match await self.gtags.clang_searcher.is_file_referenced(Path(p)):
                # we had an error so we can't rule it out
                case Err():
                    return True
                # if we know if it is referenced, we can use that information
                case Ok(is_referenced):
                    return is_referenced
        # we don't have clang to tell us, so we can't rule it out
        return True