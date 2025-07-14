from asyncio.subprocess import PIPE, DEVNULL

import asyncio
import io
import regex
import xml.etree.ElementTree as ET


from crs.config import CRSROOT, CRS_LOAD_OPTIONS
from crs.modules.project import Project, DEFAULT_LIB_FUZZING_ENGINE, DEFAULT_POV_TIMEOUT
from crs.common import docker, process
from crs.common.alru import async_once, alru_cache
from crs.common.types import Ok, Err, CRSError, Result
from crs.common.utils import only_ok, require, requireable, trim_tool_output

from crs_rust import logger

JDB_DEBUG_OPTS = "JAVA_OPTS=-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005"
JDB_CONNECT_CMD = "jdb -sourcepath /out/src -attach 5005"

BREAKPOINT_NOT_HIT_ERR = "the breakpoint was not hit"

class Debugger():
    CMD_PROMPT_REGEX = regex.compile(r"^File '([^']+)':$")
    CRS_LIBFUZZING_ENGINE = CRSROOT / ".." / "utils" / "wrapper_engine" / "libFuzzingEngine.a"
    CRS_JAVAC_WRAPPER = CRSROOT / ".." / "utils" / "javac_wrapper" / "javac"

    def __init__(self, project: Project):
        self.project = project.new_fork()

    @requireable
    async def _find_src_files(self, name: str) -> Result[list[str]]:
        tree = require(await self.project.vfs.parent.tree())
        return Ok(tree.get_full_paths(name).unwrap_or([]))

    async def find_maven_files(self) -> Result[list[str]]:
        """
        Recursively find all pom.xml files in the given directory.

        :param root_dir: The root directory to search.
        :return: A list of paths to pom.xml files.
        """
        assert self.project.info.language == "jvm", "only java projects can find maven files"
        return await self._find_src_files("pom.xml")

    async def enable_maven_debug_build(self, pom_path: str):
        """
        Modify the given pom.xml to enable debug builds.

        :param pom_path: Path to the pom.xml file.
        """
        assert self.project.info.language == "jvm", "only java projects can enable maven debug"
        data = await self.project.vfs.read(pom_path)
        tree = ET.parse(io.BytesIO(data))
        root = tree.getroot()

        # Define namespaces (Maven files often use namespaces)
        namespaces = {'': 'http://maven.apache.org/POM/4.0.0'}
        ET.register_namespace('', namespaces[''])

        # Locate or create the maven-compiler-plugin configuration
        build = root.find("./build", namespaces)
        if build is None:
            build = ET.SubElement(root, "build")

        # Use pluginManagement section instead, if exists
        plugin_management = build.find("pluginManagement", namespaces)
        if plugin_management is not None:
            build = plugin_management

        plugins = build.find("plugins", namespaces)
        if plugins is None:
            plugins = ET.SubElement(build, "plugins")

        # Find maven-compiler-plugin or create it
        compiler_plugin = None
        for plugin in plugins.findall("plugin", namespaces):
            artifact_id = plugin.find("artifactId", namespaces)
            if artifact_id is not None and artifact_id.text == "maven-compiler-plugin":
                compiler_plugin = plugin
                break

        if compiler_plugin is None:
            compiler_plugin = ET.SubElement(plugins, "plugin")
            ET.SubElement(compiler_plugin, "artifactId").text = "maven-compiler-plugin"

        # Ensure configuration section exists
        configuration = compiler_plugin.find("configuration", namespaces)
        if configuration is None:
            configuration = ET.SubElement(compiler_plugin, "configuration")

        # Set debug options
        debug = configuration.find("debug", namespaces)
        if debug is None:
            debug = ET.SubElement(configuration, "debug")
        debug.text = "true"

        optimize = configuration.find("optimize", namespaces)
        if optimize is None:
            optimize = ET.SubElement(configuration, "optimize")
        optimize.text = "false"

        buf = io.BytesIO()
        tree.write(buf, encoding="utf-8", xml_declaration=True)
        # Write back the modified pom.xml
        await self.project.editor.write_tracked(pom_path, buf.getvalue())

    async def find_ant_build_files(self) -> Result[list[str]]:
        """
        Recursively find all ant build.xml files in the given directory.

        :param root_dir: The root directory to search.
        :return: A list of paths to build.xml files.
        """
        assert self.project.info.language == "jvm", "only java projects can find maven files"
        return await self._find_src_files("build.xml")

    async def enable_ant_debug_build(self, build_xml_path: str):
        """
        Edit an Ant build.xml file to enable debug builds.
        :param file_path: Path to the Ant build file (build.xml)
        """
        # Parse the XML file
        data = await self.project.vfs.read(build_xml_path)
        tree = ET.parse(io.BytesIO(data))
        root = tree.getroot()

        # Namespace handling (Ant typically doesn't use namespaces)
        namespace = '' if root.tag.startswith("project") else '{http://ant.apache.org}'

        # Find all <javac> elements and set debug="true"
        modified = False
        for javac in root.findall(f".//{namespace}javac"):
            if javac.get('debug') != 'true':
                _ = javac.set('debug', 'true')
                modified = True

        if not modified:
            return

        # Save the changes
        buf = io.BytesIO()
        tree.write(buf, encoding="utf-8", xml_declaration=True)
        # Write back the modified build.xml
        await self.project.editor.write_tracked(build_xml_path, buf.getvalue())

    @async_once
    @requireable
    async def _init_maven_debug(self):
        for pom_path in require(await self.find_maven_files()):
            try:
                await self.enable_maven_debug_build(pom_path)
            except Exception as e:
                logger.warning("Error editing maven file {pom_path}: {err}", pom_path=pom_path, err=e)
        return Ok(None)

    @async_once
    @requireable
    async def _init_ant_debug(self):
        for build_xml_path in require(await self.find_ant_build_files()):
            try:
                await self.enable_ant_debug_build(build_xml_path)
            except Exception as e:
                logger.warning("Error editing ant file {build_xml_path}: {err}", build_xml_path=build_xml_path, err=e)
        return Ok(None)

    @alru_cache(maxsize=None, filter=only_ok)
    @requireable
    async def init(self) -> Result[None]:
        if self.project.info.language == "jvm":
            require(await self._init_maven_debug())
            require(await self._init_ant_debug())
        return Ok(None)

    @alru_cache(maxsize=None, filter=only_ok)
    async def artifacts(self):
        cfg = self.project.info.debug_build_config.model_copy()
        res = await self.project.build(
            cfg,
            mounts={
                self.CRS_LIBFUZZING_ENGINE: DEFAULT_LIB_FUZZING_ENGINE,
                self.CRS_JAVAC_WRAPPER: "/opt/javac"
            }
        )
        if res.is_err():
            logger.error(f"{self.project.name} debug build failed, trying fallback")
            cfg.CFLAGS = cfg.CFLAGS.replace("-fno-inline", "")
            res = await self.project.build(
                cfg,
                mounts={
                    self.CRS_LIBFUZZING_ENGINE: DEFAULT_LIB_FUZZING_ENGINE,
                    self.CRS_JAVAC_WRAPPER: "/opt/javac"
                }
            )
        return res

    async def supports_debugging(self):
        match await self.init():
            case Err(e):
                return False
            case Ok(_):
                pass
        match await self.artifacts():
            case Err(e):
                logger.warning("Debug build failed!", error=e)
                return False
            case Ok(_):
                pass
        return (await self.project.init_harness_info()).is_ok()

    @requireable
    async def gdb_exec(self, harness_num: int, input: bytes, breakpoint: str, commands: list[str]) -> Result[str]:
        """
        Runs the harness on {input}, breaks at {breakpoint}, and runs the {commands}.
        Returns all output from gdb
        """
        if not await self.supports_debugging():
            return Err(CRSError(f"This project doesn't support debugging."))
        if self.project.info.language not in {"c", "c++"}:
            return Err(CRSError("gdb is only supported for c and c++ projects"))
        if "\n" in breakpoint:
            return Err(CRSError("invalid character in breakpoint: \\n"))
        if any("\n" in cmd for cmd in commands):
            return Err(CRSError("invalid character in command: \\n"))
        if any("end" == cmd.strip() for cmd in commands):
            return Err(CRSError("invalid command: end"))

        harness = require(self.project.check_harness(harness_num))
        cmd_lines = "\n".join(commands)
        gdb_script = f"b {breakpoint}\ncommands\np \"breakpoint hit\"\n{cmd_lines}\ncontinue\nend\nrun\n".encode()

        gdb_cmd = [
            "bash", "-c",
            f"FUZZER=\"{harness.name}\" source /load_options.sh && gdb -batch -x /gdbscript --args \"/out/{harness.name}\" /input"
        ]
        reader = process.Reader()
        try:
            async with require(await self.artifacts()).run(mounts={CRS_LOAD_OPTIONS: "/load_options.sh"}) as run:
                require(await docker.vwrite(run, {"/input": input, "/gdbscript": gdb_script}))
                proc = await run.exec(*gdb_cmd, stdout=PIPE, stderr=PIPE)
                reader = process.Reader(proc)
                res = await reader.communicate()
        except TimeoutError:
            res = reader.result(timedout=True)

        if res.timedout:
            return Err(CRSError(f"gdb command timed out: {trim_tool_output(res.output)}"))
        if res.returncode != 0:
            return Err(CRSError(f"gdb command failed: {trim_tool_output(res.output)}"))
        if "breakpoint hit" not in res.output:
            return Err(CRSError(BREAKPOINT_NOT_HIT_ERR))
        lines = res.output.splitlines()
        for i, l in enumerate(lines):
            if l.startswith("Breakpoint 1"):
                output = "\n".join(lines[i:])
                return Ok(trim_tool_output(output))
        return Err(CRSError(f"couldn't identify gdb output: {res.output}"))

    @requireable
    async def jdb_exec(self, harness_num: int, input: bytes, breakpoint: str, commands: list[str]) -> Result[str]:
        """
        Runs the harness on {input}, breaks at {breakpoint}, and runs the {commands}.
        Returns all output from jdb
        """
        if not await self.supports_debugging():
            return Err(CRSError(f"This project doesn't support debugging."))
        if not self.project.info.language == "jvm":
            return Err(CRSError("jdb is only supported for jvm projects"))
        if "\"" in breakpoint:
            return Err(CRSError("breakpoint contains invalid character: \""))
        if any('"' in cmd for cmd in commands):
            return Err(CRSError("command contains invalid character: \""))

        output_chunks: list[bytes] = []
        breakpoint_hit = False
        async def interactor(stdout: asyncio.StreamReader, stdin: asyncio.StreamWriter):
            nonlocal output_chunks, breakpoint_hit
            try:
                _ = await stdout.readuntil(b"Initializing jdb")
                output_chunks.append(await stdout.readuntil(b">"))
                break_cmd = f"stop at {breakpoint}\r\n" if ":" in breakpoint else f"stop in {breakpoint}\r\n"
                stdin.write(break_cmd.encode())
                output_chunks.append(await stdout.readuntil(b"[1]"))
                stdin.write(b"cont\r\n")
                while True:
                    while True:
                        output_chunks.append((line := await stdout.readline()))
                        if not line:
                            return
                        if b"Stopping due to deferred breakpoint errors." in line: return
                        if b"The application exited" in line: return
                        if b"Exception occurred" in line and b"(uncaught)" in line: return
                        if b"Breakpoint hit" in line: break
                    breakpoint_hit = True
                    output_chunks.append(await stdout.readuntil(b"[1]"))
                    # at the breakpoint, send the commands
                    for cmd in commands:
                        stdin.write(f"{cmd}\r\n".encode())
                        output_chunks.append(await stdout.readuntil(b"[1]"))
                    stdin.write(b"cont\r\n")
            except asyncio.IncompleteReadError as e:
                logger.warning(f"Incomplete read in jdb_exec interactor: {e}")
            except ValueError as e:
                logger.warning(f"ValueError in jdb_exec interactor: {e}")

        harness = require(self.project.check_harness(harness_num))

        cmd = f"(cd /out && {JDB_DEBUG_OPTS} /out/{harness.name} /input) & {JDB_CONNECT_CMD}"
        timedout = False
        returncode = None
        try:
            timeout = 2 * DEFAULT_POV_TIMEOUT # jdb overhead is significant
            async with require(await self.artifacts()).run(timeout=timeout) as run:
                require(await docker.vwrite(run, {"/input": input}))
                proc = await run.exec("bash", "-c", cmd, stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
                assert proc.stdout is not None
                assert proc.stdin is not None
                returncode, _ = await asyncio.gather(
                    proc.wait(),
                    interactor(stdout=proc.stdout, stdin=proc.stdin)
                )
        except TimeoutError:
            timedout = True

        output = trim_tool_output("".join(c.decode(errors="replace") for c in output_chunks))
        if timedout:
            return Err(CRSError(f"jdb command timed out: {output}", extra={
                "note": (
                    "It is possible this was a sporadic timeout. IF you are confident that your command shouldn't cause a timeout, "
                    "you may want to retry (BUT AT MOST ONCE)."
                )
            }))
        if returncode != 0:
            return Err(CRSError(f"jdb command failed: {output}"))
        if not breakpoint_hit:
            return Err(CRSError(BREAKPOINT_NOT_HIT_ERR))
        return Ok(output)
