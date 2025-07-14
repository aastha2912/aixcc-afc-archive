import asyncio
import orjson
import regex

from aiosqlite import Connection
from asyncio.subprocess import DEVNULL
from collections import defaultdict
from dataclasses import dataclass
from crs.common.aio import Path
from typing import Any, Callable, Optional, TypedDict, cast

from crs.modules.graph import ReachabilityGraph
from crs.modules.project import Harness, Project, DEFAULT_POV_TIMEOUT
from crs.config import CRS_LOAD_OPTIONS, JACOCO_PARSER, LCOV_PARSER, LLVM_COV
from crs.common import docker, joern
from crs.common.alru import alru_cache
from crs.common.constants import MAX_POV_LENGTH
from crs.common.sqlite import SQLiteDB
from crs.common.path import PathSuffixTree
from crs.common.types import Ok, Err, CRSError, Result
from crs.common.utils import only_ok, require, requireable

from crs_rust import logger

COVERAGE_BATCH_TIMEOUT = 15 * 60
COVERAGE_DB_FILE_NAME = "cov.sqlite3"
COVERAGE_BMP_FILE = "cov.bmp"

LCOV_FILE_REGEX = regex.compile(r"^SF:([^']+)\n$")
LCOV_FUNC_REGEX = regex.compile(r"^FNDA:(\d+),(?:[^:]*:)?([a-zA-Z_][a-zA-Z0-9_]*)\n$")
LCOV_LINE_REGEX = regex.compile(r"^DA:(\d+),(\d+)\n$")

class CoverageMap():
    def __init__(self, tree: PathSuffixTree):
        # map function_name -> file_path -> bool
        self.funcs: dict[str, dict[str, bool]] = defaultdict(dict[str, bool])
        # map file_path -> line num -> bool
        self.lines: dict[str, dict[int, bool]] = defaultdict(dict[int, bool])
        self.tree = tree

    @requireable
    def add_func_hit(self, func: str, path: Path | str, val: bool) -> Result[None]:
        normalized = require(self.tree.normalize_path(path))
        if normalized in self.funcs[func]: self.funcs[func][normalized] = self.funcs[func][normalized] or val
        else: self.funcs[func][normalized] = val
        return Ok(None)

    @requireable
    def add_line_hit(self, path: Path | str, line: int, val: bool) -> Result[None]:
        normalized = require(self.tree.normalize_path(path))
        if line in self.lines[normalized]: self.lines[normalized][line] = self.lines[normalized][line] or val
        else:
            self.lines[normalized][line] = val
        return Ok(None)

    def iter_covered_funcs(self):
        for func, pmap in self.funcs.items():
            for path, hit in pmap.items():
                if hit:
                    yield (func, path)

    def iter_missed_funcs(self):
        for func, pmap in self.funcs.items():
            for path, hit in pmap.items():
                if not hit:
                    yield (func, path)

    def iter_covered_lines(self):
        for path, lmap in self.lines.items():
            for line, hit in lmap.items():
                if hit:
                    yield (path, line)

    def iter_missed_lines(self):
        for path, lmap in self.lines.items():
            for line, hit in lmap.items():
                if not hit:
                    yield (path, line)

    @requireable
    async def supports_function(self, function: str, path: Optional[str] = None) -> Result[bool]:
        """
        Whether the coverage map supports the given `function` defined in `path`.
        If `path` is None, this function will error if there are multiple functions
        with that name
        """
        supported_paths = self.funcs[function]
        if len(supported_paths) == 0:
            return Ok(False)
        if not path and len(supported_paths) == 1:
            return Ok(True)
        if not path:
            return Err(CRSError("path must be provided to resolve ambiguity"))
        return Ok(require( self.tree.normalize_path(path)) in supported_paths)

    @requireable
    async def covered(self, function: str, path: Optional[str] = None) -> Result[bool]:
        """
        Whether the coverage map covered the given `function` defined in `path`.
        Note: will error if not `supports_function(function, path)`, so either
        check that first or catch the Exception
        """
        assert require(await self.supports_function(function, path))
        supported_paths = self.funcs[function]
        if not path and len(supported_paths) == 1:
            return Ok(list(supported_paths.values())[0])
        assert path is not None # null path with len(supported_paths) != 1 would be caught already
        return Ok(supported_paths[require(self.tree.normalize_path(path))])

    @requireable
    def line_covered(self, path: str, line: int) -> Result[bool]:
        """
        Whether the coverage map covered the given `path` and `line`.
        """
        return Ok(self.lines[require(self.tree.normalize_path(path))].get(line, False))

SCHEMA = [
    f"""
    CREATE TABLE IF NOT EXISTS inputs (
        id INTEGER PRIMARY KEY,
        contents BLOB NOT NULL CHECK(length(contents) < {MAX_POV_LENGTH}),
        UNIQUE(contents)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS coverage (
        harness_num INTEGER NOT NULL,
        file TEXT NOT NULL,
        line INTEGER NOT NULL,
        input_id INTEGER NOT NULL,
        FOREIGN KEY (input_id) REFERENCES inputs(id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS branchflips (
        id INTEGER PRIMARY KEY,
        harness_num INTEGER NOT NULL,
        target TEXT NOT NULL,
        closest TEXT NOT NULL,
        input_id INTEGER NOT NULL,
        FOREIGN KEY (input_id) REFERENCES inputs(id)
    );
    """,
]

@dataclass
class Frontier:
    target: str
    closest: str
    harness_num: int
    input_id: int
    score: float

class CoverageDB(SQLiteDB):
    def __init__(self, db_path: Path):
        self.lock = asyncio.Lock()
        super().__init__(db_path, SCHEMA)

    async def store_coverage_hitlist_with_conn(self, conn: Connection, harness_num: int, contents: bytes, cov: dict[str, list[int]]) -> int:
        # Insert or fetch the input id
        async with conn.execute(
            """
            INSERT INTO inputs (contents)
            VALUES (?)
            ON CONFLICT (contents)
            DO UPDATE SET id = id
            RETURNING id;
            """,
            (contents,)
        ) as cursor:
            input_id: int = int((await cursor.fetchone())[0]) # type: ignore

        _ = await conn.executemany(
            """
            INSERT INTO coverage (harness_num, input_id, file, line)
            VALUES (?, ?, ?, ?);
            """,
            ((harness_num, input_id, f, line) for f, lines in cov.items() for line in lines)
        )

        return input_id

    async def store_coverage(self, harness_num: int, contents: bytes, cov: CoverageMap):
        async with self.lock, self.sqlite_connect() as conn:
            # Insert or fetch the input id
            async with conn.execute(
                """
                INSERT INTO inputs (contents)
                VALUES (?)
                ON CONFLICT (contents)
                DO UPDATE SET id = id
                RETURNING id;
                """,
                (contents,)
            ) as cursor:
                input_id: int = (await cursor.fetchone())[0] # type: ignore

            # Batch insert into the `coverage` table
            coverage_data: list[tuple[int, int, str, int]] = [(harness_num, input_id, file, line) for file, line in cov.iter_covered_lines()]
            _ = await conn.executemany(
                """
                INSERT INTO coverage (harness_num, input_id, file, line)
                VALUES (?, ?, ?, ?);
                """,
                coverage_data
            )
            await conn.commit()

    async def get_input_for_line(self, harness_num: int, file: str, line: int) -> Result[bytes]:
        async with self.lock, self.sqlite_connect() as conn:
            async with conn.execute(
                """
                SELECT contents
                FROM inputs
                JOIN coverage ON inputs.id = coverage.input_id
                WHERE harness_num = ? AND file = ? AND line = ?
                LIMIT 1;
                """,
                (harness_num, file, line)
            ) as cursor:
                row = await cursor.fetchone()
            if row:
                return Ok(row[0])
            else:
                return Err(CRSError("No covering input found"))

    async def foreach_covered_lines(self, func: Callable[[int, str, int, int], Any]):
        async with self.lock, self.sqlite_connect() as conn:
            async with conn.execute(
                """
                SELECT min(input_id), file, line, harness_num
                FROM coverage
                GROUP BY file, line, harness_num;
                """,
            ) as cursor:
                async for row in cursor:
                    func(row[0], row[1], row[2], row[3])

    async def get_input(self, input_id: int) -> Result[bytes]:
        async with self.lock, self.sqlite_connect() as conn:
            async with conn.execute(
                """
                SELECT contents
                FROM inputs
                WHERE id = ?;
                """,
                (input_id,)
            ) as cursor:
                row = await cursor.fetchone()
            if row:
                return Ok(row[0])
            else:
                return Err(CRSError("No input found"))

    async def dedup_frontiers(self, frontiers: list[Frontier], update_db: bool = False) -> list[Frontier]:
        async with self.lock, self.sqlite_connect() as conn:
            _ = await conn.execute("DROP TABLE IF EXISTS tmp_frontiers")
            _ = await conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS tmp_frontiers (
                    id INTEGER NOT NULL,
                    target TEXT NOT NULL,
                    closest TEXT NOT NULL
                );
            """)
            _ = await conn.executemany(
                """
                INSERT INTO tmp_frontiers (id, target, closest)
                VALUES (?, ?, ?);
                """,
                ((i, f.target, f.closest) for i, f in enumerate(frontiers))
            )

            # dedup the trials
            async with conn.execute(
                """
                SELECT t.id
                FROM tmp_frontiers t
                WHERE NOT EXISTS (
                    SELECT 1 FROM branchflips b
                    WHERE t.target = b.target AND t.closest = b.closest
                );
                """
            ) as cursor:
                frontiers = [frontiers[cast(int, row[0])] for row in await cursor.fetchall()]

            if update_db:
                # Batch insert into the `branchflips` table
                _ = await conn.executemany(
                    """
                    INSERT INTO branchflips (harness_num, target, closest, input_id)
                    VALUES (?, ?, ?, ?);
                    """,
                    [(f.harness_num, f.target, f.closest, f.input_id) for f in frontiers]
                )
                await conn.commit()

        return frontiers

class CovOutput(TypedDict):
    lines: dict[str, list[int]]

class EmptyDict(TypedDict):
    pass

@dataclass
class CoverageLineInfo:
    covered: dict[tuple[int, str], Result[tuple[bytes, CovOutput|EmptyDict]]]

class CoverageAnalyzer():
    def __init__(self, project: Project):
        self.project = project
        self.searcher = project.searcher
        self.new_coverage = asyncio.Condition()
        self.db = CoverageDB(project.data_dir / COVERAGE_DB_FILE_NAME)
        self.graph = ReachabilityGraph()
        self.running = False
        self.bmp_file = project.data_dir / COVERAGE_BMP_FILE

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def init(self) -> Result[None]:
        json_dat = require(await joern.callgraph(self.project))
        await self.graph.initialize_graph(json_dat, require(await self.project.vfs.parent.tree()))
        await self.db.foreach_covered_lines(self.graph.add_new_hit)
        return Ok(None)

    @alru_cache(maxsize=None, filter=only_ok)
    async def artifacts(self):
        cfg = self.project.info.coverage_build_config.model_copy()
        res = await self.project.build(cfg)
        if res.is_err():
            logger.error(f"{self.project.name} coverage build failed, trying fallback")
            cfg.CFLAGS = cfg.CFLAGS.replace("-fno-inline", "")
            res = await self.project.build(cfg)
        return res

    async def supports_coverage(self):
        match await self.artifacts():
            case Ok():
                pass
            case Err(e):
                logger.warning("Coverage build failed!", error=e)
                return False
        _ = await self.project.init_harness_info()
        return True

    @staticmethod
    def _inner_cmd_c(harnesses: list[Harness], filename: str, harness_num: int) -> str:
        return (
            f"source /tmp/env_{harnesses[harness_num].name}.sh && cd $OUT && "
            f"LLVM_PROFILE_FILE=/tmp/cov_{harness_num}_{filename}.profraw $OUT/{harnesses[harness_num].name} $CUSTOM_LIBFUZZER_OPTIONS /input_{harness_num}_{filename} && "
            f"profraw_update.py $OUT/{harnesses[harness_num].name} -i /tmp/cov_{harness_num}_{filename}.profraw && "
            f"llvm-profdata merge /tmp/cov_{harness_num}_{filename}.profraw -o /tmp/cov_{harness_num}_{filename}.profdata && "
            f"llvm-cov export --instr-profile=/tmp/cov_{harness_num}_{filename}.profdata --path-equivalence=/,$OUT "
            f" $OUT/{harnesses[harness_num].name} --format=lcov > /cov_{harness_num}_{filename}.cov"
        )

    @staticmethod
    def _inner_cmd_java(harnesses: list[Harness], filename: str, harness_num: int) -> str:
        jacoco_args = (
            f"destfile=/tmp/cov_{harness_num}_{filename}.exec,classdumpdir=/tmp/classdump_{harness_num}_{filename},"
            f"excludes=com.code_intelligence.jazzer.*\\:com.sun.tools.attach.VirtualMachine"
        )
        return (
            f"source /tmp/env_{harnesses[harness_num].name}.sh && cd $OUT && "
            f"$OUT/{harnesses[harness_num].name} --nohooks --instrumentation_excludes=** '--additional_jvm_args=-javaagent\\:/opt/jacoco-agent.jar={jacoco_args}:-XX\\:ActiveProcessorCount=2' "
            f"$CUSTOM_LIBFUZZER_OPTIONS /input_{harness_num}_{filename} && "
            f"java -jar /opt/jacoco-cli.jar report /tmp/cov_{harness_num}_{filename}.exec "
            f"--xml /cov_{harness_num}_{filename}.cov --classfiles /tmp/classdump_{harness_num}_{filename}"
        )

    @requireable
    async def collect_coverages(
        self,
        contents: dict[tuple[int, str], bytes],
        cores: int = 1,
        scope: Optional[docker.DockerScope] = None,
        ignore_bmp: bool = False,
    ) -> Result[CoverageLineInfo]:
        harnesses = require(await self.project.init_harness_info())
        used_harness_nums = {k[0] for k in contents}

        env = { "COVERAGE_EXTRA_ARGS": self.project.info.coverage_extra_args }

        if self.project.info.language == "jvm":
            # jazzer has lots of overhead
            cores = cores//2

        sem = asyncio.Semaphore(max(cores, 1))

        async def inner_cmd(filename: str, harness_num: int):
            async with sem:
                if self.project.info.language == "jvm":
                    cmd = self._inner_cmd_java(harnesses, filename, harness_num)
                else:
                    cmd = self._inner_cmd_c(harnesses, filename, harness_num)
                err = Err(CRSError("unknown error"))
                try:
                    async with asyncio.timeout(DEFAULT_POV_TIMEOUT):
                        proc = await run.exec("bash", "-c", cmd, stdout=DEVNULL, stderr=DEVNULL)
                        if await proc.wait() != 0:
                            err = Err(CRSError("proc failed when getting coverage"))
                except TimeoutError:
                    err = Err(CRSError("timed out trying to get coverage"))
                finally:
                    errs[filename] = err

        # load_options.sh takes ~100ms because it invokes python several times
        init_env_cmd = " && ".join(
            f"set -a && cd $OUT && FUZZER=\"{harnesses[i].name}\" "
            f"source /load_options.sh && declare -px > /tmp/env_{harnesses[i].name}.sh"
            for i in used_harness_nums
        )

        parser = JACOCO_PARSER if self.project.info.language == "jvm" else LCOV_PARSER

        try:
            async with require(await self.artifacts()).run(
                env=env,
                timeout=COVERAGE_BATCH_TIMEOUT,
                mounts={
                    CRS_LOAD_OPTIONS: "/load_options.sh",
                    LLVM_COV: "/usr/local/bin/llvm-cov",
                    parser: "/usr/local/bin/cov_parser",
                },
                scope=scope,
            ) as run:
                to_write = {f"/input_{idx}_{fname}": content for (idx, fname), content in contents.items()}
                if not ignore_bmp and await self.bmp_file.exists():
                    to_write["/bmp"] = await self.bmp_file.read_bytes()
                require(await docker.vwrite(run, to_write))
                # load env variables once for perf
                if await (await run.exec("bash", "-c", init_env_cmd)).wait() != 0:
                    return Err(CRSError("error setting up initial env"))

                errs: dict[str, Err[CRSError]] = {}
                async with asyncio.TaskGroup() as tg:
                    for harness_num, filename in contents:
                        _ = tg.create_task(inner_cmd(filename, harness_num), name=f"collect_coverages() inner_cmd(filename={filename!r}) project={self.project.name}")

                proc = await run.exec("bash", "-c", "cov_parser --out /tmp/covered.json --bitmap /bmp /cov_*.cov")
                if await (proc).wait() != 0:
                    return Err(CRSError("error parsing cov output"))

                res = CoverageLineInfo(covered={})
                output = require(await docker.vread_many(run, {"/tmp/covered.json", "/bmp"}))
                json_dat = output["tmp/covered.json"]
                if not ignore_bmp:
                    _ = await self.bmp_file.write_bytes(output["bmp"])
                covered = await asyncio.to_thread(orjson.loads, json_dat)
                for (harness_num, filename), data in contents.items():
                    if (entries := covered.get(f"/cov_{harness_num}_{filename}.cov")) is None:
                        res.covered[harness_num, filename] = errs.get(filename, Err(CRSError("no coverage for file")))
                        continue
                    res.covered[harness_num, filename] = Ok((data, entries))

                return Ok(res)
        except TimeoutError:
            return Err(CRSError("coverage collection timed out"))

    @requireable
    async def update_coverages(
        self,
        contents: dict[tuple[int, str], bytes],
        cores: int = 1,
        scope: Optional[docker.DockerScope] = None,
    ) -> Result[dict[tuple[int, str], Result[None]]]:
        _ = await self.init()
        if self.running:
            logger.error(f"update coverage running concurrently for {self.project.name}?!")
        self.running = True
        res: dict[tuple[int, str], Result[None]] = {}
        covs = require(await self.collect_coverages(contents, cores, scope))
        tree = require(await self.project.vfs.parent.tree())
        async with self.db.sqlite_connect() as conn: # type: ignore
            for (harness_num, fname), cov_info in covs.covered.items():
                match cov_info:
                    case Ok((data, entries)):
                        if 'lines' in entries:
                            translated = {
                                (tree.normalize_path(k)).unwrap_or(k):v
                                for k,v in entries['lines'].items()
                            }
                            input_id = await self.db.store_coverage_hitlist_with_conn(conn, harness_num, data, translated)
                            # if there was new coverage, update our graph
                            # especially for the first coverage data, this can take some CPU, let's not block our main thread
                            _ = await asyncio.to_thread(self.graph.add_new_hits, input_id, harness_num, translated)
                        res[(harness_num, fname)] = Ok(None)
                    case Err() as e:
                        res[(harness_num, fname)] = e
            self.running = False
            await conn.commit()
        return Ok(res)

    @requireable
    async def compute_coverage(self, harness_num: int, contents: bytes) -> Result[CoverageMap]:
        match await self.collect_coverages({(harness_num, "input"): contents}, cores=1, scope=None, ignore_bmp=True):
            case Err() as e:
                return e
            case Ok(cov):
                pass
        match cov.covered.get((harness_num, "input"), Err(CRSError("failed to gather coverage"))):
            case Err() as e:
                return e
            case Ok((_, entries)):
                tree = require(await self.project.vfs.parent.tree())
                cm = CoverageMap(tree)
                for file, lines in entries.get('lines', {}).items():
                    for line in lines:
                        _ = cm.add_line_hit(file, line, True)
                return Ok(cm)

    LineCoverageInfo = TypedDict(
        "LineCoverageInfo",
        {"line_reached": bool, "response": str}
    )

    @requireable
    async def query_statically_reachable(self, target_file: str, target_line: int) -> Result[tuple[set[int], set[int]]]:
        """
        Attempts to answer "can the given file and line be reached from user input".
        Note: be mindful of path normalization for target_file
        """
        _ = await self.init()
        match self.graph.get_info_for_line(target_file, target_line):
            case None:
                return Err(CRSError(f"file {target_file}:{target_line} not found in reachability data"))
            case _, info:
                return Ok((info.direct_hits, info.reachable_hits))

    def query_hit(self, target_file: str, target_line: int) -> bool:
        """
        Attempts to answer "IS the given file and line be reached from user input".
        Note: this assumes the coverage graph is already initialized!
        Note: be mindful of path normalization for target_file
        """
        match self.graph.get_info_for_line(target_file, target_line):
            case None:
                return False
            case _, info:
                return bool(info.direct_hits)

    async def query_frontier(self) -> list[Frontier]:
        """
        Returns a list of (target destination (file:line start:line end:funcname), closest direct hit, harness id, input id)
        sorted in descending order of "depth" (so the first entry should be highest priority to try to hit) 
        """
        _ = await self.init()
        return [
            Frontier(node.desc, node.closest.entry, node.closest.harness, node.closest.input_id, score)
            for node, score in self.graph.get_frontier()
            if node.closest is not None
        ]

    @requireable
    async def query_coverage(
        self, harness_num: int, pov_python: str, target_file: str, target_line: int
    ) -> Result[LineCoverageInfo]:
        """
        Attempts to answer "does this PoV reach this target source line" for the given
        {pov_python} code reaching the {target_line} inside the {target_file}
        from the harness given by {harness_num}.
        <requirements>
        The {pov_python} must be valid and produce a PoV that runs and does not time
        out for the given harness. It must produce a file named "input.bin".
        IMPORTANT: It will be run in a new interpreter and must define or import
        everything referenced.
        </requirements>
        <important>
        Use this tool to help investigate the execution flow when running a candidate PoV.
        </important>

        Parameters
        ----------
        harness_num : int
            The (0 indexed) harness against which to test
        pov_python : str
            The python code we will run. This will be executed with no input, and
            must produce a file named "input.bin". It will be run in a new interpreter and
            must define or import everything referenced.
        target_file : str
            The path to the source file
        target_line : int
            The line number in the {target_file}
        """
        contents = require(await self.project.build_pov(pov_python))
        return await self.query_coverage_raw(
            harness_num=harness_num,
            pov_bytes=contents,
            target_file=target_file,
            target_line=target_line,
        )

    @requireable
    async def query_coverage_raw(
        self, harness_num: int, pov_bytes: bytes, target_file: str, target_line: int
    ) -> Result[LineCoverageInfo]:
        """
        Attempts to answer "does this PoV get to this target function" for the given
        {pov_bytes} reaching the {target_function} inside the {target_file}
        from the harness given by {harness_num}.
        If the PoV *does not* reach the target, it attempts to find functions related
        to {target_function} that are reached. Related functions may include:
        1. Functions that may call {target_function} within a few steps
        2. Functions which near {target_function} in the codebase
        <important>
        Use this tool to help investigate the execution flow when running a candidate PoV.
        </important>


        Parameters
        ----------
        harness_num : int
            The (0 indexed) harness against which to test
        pov_bytes : bytes
            The pov input to run
        target_file : str
            The path to the file in which the target_function resides
        target_line : int
            The line number in the {target_file}
        """
        if not await self.supports_coverage():
            return Err(CRSError("This project code does not support coverage queries"))
        _ = require(self.project.check_harness(harness_num))
        cov = require(await self.compute_coverage(harness_num, pov_bytes))
        before, after = None, None
        response = f"{target_file}:{target_line} was reached."
        if not (line_reached := require(cov.line_covered(target_file, target_line))):
            for f, lines in cov.lines.items():
                if not target_file.endswith(f): continue
                for l, hit in lines.items():
                    if not hit: continue
                    if l < target_line and (before is None or l > before):
                        before = l
                    elif l > target_line and (after is None or l < after):
                        after = l
            response = f"{target_file}:{target_line} was not reached."
            if before is None and after is None:
                response += f"\nIn fact, no code in {target_file} was reached."
            if before is not None:
                response += f"\nThe nearest preceeding reached line was {target_file}:{before}"
                if (defn := await self.project.searcher.enclosing_definition(target_file, before)).is_ok():
                    response += f" in `{defn.unwrap()[0]}`."
            if after is not None:
                response += f"\nThe nearest following reached line was {target_file}:{after}."
                if (defn := await self.project.searcher.enclosing_definition(target_file, after)).is_ok():
                    response += f" in `{defn.unwrap()[0]}`."
        return Ok(CoverageAnalyzer.LineCoverageInfo(line_reached=line_reached, response=response))

    @alru_cache(maxsize=2048, filter=only_ok)
    @requireable
    async def _defn_location(self, name: str, path: str):
        # TODO: return a list of all locations?
        defn = require(await self.searcher.find_definition(name, path))[0]
        return Ok((defn.file_name, defn.defs[0].line))

    @requireable
    async def find_path(self, sources: list[tuple[str, str]], sink: tuple[str, str]):
        tree = require(await self.project.vfs.parent.tree())
        async with asyncio.TaskGroup() as tg:
            sink_res, *src_ress = await asyncio.gather(*[
                tg.create_task(self._defn_location(name, path), name='_defn_location')
                for name, path in [sink] + sources
            ])
        sink_loc = require(sink_res)
        src_locs = [src_res.unwrap() for src_res in src_ress if src_res.is_ok()]
        if len(src_locs) == 0:
            return Err(CRSError("no source locations found for source defns"))
        elif len(src_locs) < len(sources):
            logger.warning("some source locations could not be found for source defns")
        return await self.graph.find_path(tree, src_locs, sink_loc)
