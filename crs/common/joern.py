from asyncio.subprocess import PIPE
import os
from typing import TYPE_CHECKING

from crs import config
from crs.common import aio, docker
from crs.common.constants import SOURCE_CODE_EXTENSIONS
from crs.common.types import Result, Ok, Err, CRSError
from crs.common.utils import requireable, require
from crs.common.vfs import TarFS

from crs_rust import logger

if TYPE_CHECKING:
    from crs.modules.project import Project

# Dockerfile in utils/joern
JOERN_IMAGE_NAME_DOCKERHUB = "konenattheori/joern@sha256:0870a6c899229d88a434d53b26c7439d6d15f2cee1b6d01d6f79a8f2735a863f"
JOERN_IMAGE_NAME = f"{config.REGISTRY_DOMAIN}/joern" if config.REGISTRY_DOMAIN else JOERN_IMAGE_NAME_DOCKERHUB
JOERN_BUILD_TIMEOUT = 3600
JOERN_RUN_TIMEOUT = 60
CALL_GRAPH_EXPORT_TIMEOUT = 10*60

with open(config.CRSROOT / ".." / "utils" / "joern" / "make_call_graph.scala") as f:
    JOERN_CALL_GRAPH_SCRIPT = f.read()

OUTPUT_PREFIX = "OUTPUT: "

@requireable
async def build_cpg(project: "Project", bear: bool = True) -> Result[TarFS]:
    if bear and (bear_tar := await project.build_bear_tar()):
        # Good, we can use compile_commands.json from bear
        logger.info(f"Found bear tar at {bear_tar}; using it to create Joern CPG")
        cpg_tar = await project.get_joern_tar()
        using_bear = True
    else:
        cpg_tar = await project.get_joern_tar()
        using_bear = False

    if await cpg_tar.exists():
        logger.info(f"Using prebuilt CPG at {cpg_tar}")
        return Ok(await TarFS.fsopen(cpg_tar))

    run = None
    try:
        async with docker.run(JOERN_IMAGE_NAME, timeout=JOERN_BUILD_TIMEOUT) as run:
            logger.info(f"Building Joern index at {cpg_tar} in cid {run.cid}")
            
            layers = await ((await project.get_bear_vfs()).layers() if using_bear else project.vfs.layers())
            require(await docker.vwrite_layers(run, "/src", layers))
            
            async with aio.tmpfile(dir=project.data_dir, prefix=f"cpg-{cpg_tar.name}.tmp") as tf:
                cmd = [
                    "find", "/src", "-type", "f", "-size", "+3M", "-printf", r"%P\0"
                ]
                proc = await run.exec(*cmd, stdout=PIPE)
                huge_files, _ = await proc.communicate()
                
                cmd = ["joern-parse", "--output", "/tmp/cpg.bin", "/src", "--frontend-args"]
                for rel_path in huge_files.split(b"\0"):
                    rel_path = rel_path.decode(errors="replace")
                    if os.path.splitext(rel_path)[1] in SOURCE_CODE_EXTENSIONS:
                        cmd += ["--exclude", rel_path]
                if using_bear and project.info.language in {"c", "c++"}:
                    cmd.extend(["--compilation-database", "/src/compile_commands.json"])
                logger.info(f"{cmd}")
                proc = await run.exec(*cmd, stdout=PIPE, stderr=PIPE,)
                _, stderr = await proc.communicate()
                if proc.returncode != 0:
                    return Err(CRSError(f"joern-parse failed: {stderr.decode(errors="replace")}"))
                proc = await run.exec(
                    "tar", "cf", "-", "--transform", r"s|^.*/||", "-C", "/tmp", "cpg.bin",
                    stdout=tf,
                )
                if await proc.wait() != 0:
                    return Err(CRSError(f"could not copy /tmp/cpg.bin to {cpg_tar!r}"))
                await tf.path.replace(cpg_tar)
    except TimeoutError:
        logger.info(f"joern-parse timed out in cid {run.cid if run else None}")
        return Err(CRSError("joern-parse timed out"))

    logger.info(f"Joern index built at {cpg_tar}")
    return Ok(await TarFS.fsopen(cpg_tar))


@requireable
async def run_query(project: "Project", query: str, timeout: float = JOERN_RUN_TIMEOUT) -> Result[str]:
    match await build_cpg(project):
        case Ok(cpg_tar):
            pass
        case Err():
            cpg_tar = require(await build_cpg(project,  bear=False))
    run = None
    try:
        async with docker.run(JOERN_IMAGE_NAME, timeout=timeout, group=docker.DockerGroup.Misc) as run:
            logger.info(f"Running Joern query in cid {run.cid}")
            require(await docker.vwrite(run, {"/tmp/script.scala": query.encode()}))
            require(await docker.vwrite_tar(run, "/cpg", cpg_tar.path))
            proc = await run.exec(
                "joern", "--script", "/tmp/script.scala", "/cpg/cpg.bin", "--verbose",
                stdout=PIPE, stderr=PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                error_msg = stdout.decode(errors="replace") + stderr.decode(errors="replace")
                return Err(CRSError(f"Joern query failed: {error_msg}"))
    except TimeoutError:
        logger.info(f"Joern query timed out in cid {run.cid if run else None}")
        return Err(CRSError("Joern query timed out"))

    lines: list[str] = []
    for line in stdout.splitlines():
        line = line.decode(errors="replace")
        if line.startswith(OUTPUT_PREFIX):
            line = line.removeprefix(OUTPUT_PREFIX)
            lines.append(line)
    output = "\n".join(lines)
    logger.info(f"Joern query returned {len(lines)} lines {len(output)} bytes")
    return Ok(output)


@requireable
async def callgraph(project: "Project") -> Result[str]:
    callgraph_path = await project.get_joern_callgraph()
    if await callgraph_path.exists():
        logger.info(f"Using cached joern callgraph {callgraph_path}")
        return Ok(await callgraph_path.read_text())
    callgraph = require(await run_query(project, JOERN_CALL_GRAPH_SCRIPT, timeout=CALL_GRAPH_EXPORT_TIMEOUT))
    if not await callgraph_path.exists():
        async with aio.tmpfile(dir=callgraph_path.parent) as f:
            _ = await f.path.write_text(callgraph)
            await f.path.replace(callgraph_path)
    return Ok(callgraph)
