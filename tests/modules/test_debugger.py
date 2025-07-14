import pytest
import random

from pathlib import Path
from typing import TypedDict

from crs.modules.testing import TestProject
from crs.modules.debugger import Debugger

TEST_DIR = Path(__file__).parent
SUPPORTED_LANGUAGES = {"c", "c++", "jvm"}


DebuggerTest = TypedDict("DebuggerTest", {"harness_num": int, "input": bytes, "breakpoint": str, "commands": list[str], "expected": str})

PROJECT_INSTRUMENTATION_TESTS: dict[str, DebuggerTest] = {
    "tomcat-theori": {
        "harness_num": 6,
        "input": b'admin\\\x00mypasswordguess',
        "breakpoint": "org.apache.catalina.realm.JNDIRealm:1770",
        "commands": ["dump hashBytes"],
        "expected": "hashBytes = {\n15, 105, -55, 33, -3"
    },
    "afc-zookeeper": {
        "harness_num": 1,
        "input": b'192.168.0.12\x00\x00\x00\xd2\x02\x96\x49\x00\x00\x00\x00',
        "breakpoint": "org.apache.zookeeper.server.util.MessageTracker:107",
        "commands": ["dump serverAddr"],
        "expected": "serverAddr = \"192.168.0.12"
    }
}

rand = random.Random(0x13371337)

@pytest.mark.slow
async def test_debugger_commands(built_project: TestProject):
    if built_project.info.language not in SUPPORTED_LANGUAGES:
        return
    debugger = Debugger(built_project)
    assert await debugger.supports_debugging(), f"debugging not supported for project '{built_project.name}'"

    harnesses = (await built_project.init_harness_info()).unwrap()
    match built_project.info.language:
        case "c"|"c++":
            # Typical harnesses are declared like:
            # `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
            # Check the correct size is printed, but do not depend on parameter name
            res = (await debugger.gdb_exec(0, b"\x00"*101, "LLVMFuzzerTestOneInput", ["info args"])).unwrap()
            assert '= 101' in res, 'unexpected gdb output'
        case "jvm":
            breakpoint = f"{Path(harnesses[0].source).name.replace(".java", "")}.fuzzerTestOneInput"
            res = (await debugger.jdb_exec(0, b"\x00"*101, breakpoint, ['next', 'dump data'])).unwrap()
            
            # If fuzzer input is formatted using FuzzedDataProvider we expect the former.
            # If fuzzer input is byte[] we expect the latter.
            assert 'originalRemainingBytes: 101' in res or ", ".join(["0"] * 101) in res, 'unexpected jdb output'
        case _:
            raise NotImplementedError

@pytest.mark.slow
async def test_project_instrumentation(built_project: TestProject):
    if (testcase := PROJECT_INSTRUMENTATION_TESTS.get(built_project.name)) is None:
        return
    debugger = Debugger(built_project)
    assert await debugger.supports_debugging(), f"debugging not supported for project '{built_project.name}'"

    match built_project.info.language:
        case "c"|"c++":
            res = (await debugger.gdb_exec(testcase["harness_num"], testcase["input"], testcase["breakpoint"], testcase["commands"])).unwrap()
            assert testcase["expected"] in res, 'unexpected gdb output'
        case "jvm":
            res = (await debugger.jdb_exec(testcase["harness_num"], testcase["input"], testcase["breakpoint"], testcase["commands"])).unwrap()
            assert testcase["expected"] in res, 'unexpected jdb output'
        case _:
            raise NotImplementedError