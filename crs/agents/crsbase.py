import orjson

from dataclasses import dataclass, replace
from pydantic import BaseModel
from typing import Any

from crs import config
from crs.common.types import Ok, Err, Result, CRSError
from crs.modules.project import Project, Task, Harness
from crs.modules.coverage import CoverageAnalyzer
from crs.modules.debugger import Debugger
from crs.modules.search_code import Searcher

from crs_rust import logger

class SanitizerDescription(BaseModel):
    desc: str
    alt: list[str]

PROTO_SAMPLE = """
```proto
syntax = "proto3";
package main;

message Test {
    string comment = 1;
}

message Example {
    string name = 1;
    int32 age = 2;
    repeated Test t = 3;

    message Label {
        string source = 1;
    }
    repeated Label labels = 4;
}
```

```
name: "Larry"
age: 99
t: [{
    comment: "hello\\nworld"
}, {
    comment: "foo\\nbar"
}]
labels: [{
    source: "foo"
}, {
    source: "bar"
}]
```
"""

with open(config.CRSROOT / "jazzer_sanitizer_summary.json", "rb") as f:
    BASE_SANITIZERS = orjson.loads(f.read())

@dataclass(eq=False)
class CRSBase:
    """
    CRS that analyzes a single problem
    """

    task: Task
    project: Project
    searcher: Searcher
    coverage: CoverageAnalyzer
    debugger: Debugger

    @classmethod
    @config.telem_tracer.start_as_current_span("crs_base", record_exception=False)
    def from_task(cls, task: Task):
        return cls(task, task.project, task.project.searcher, task.coverage, task.debugger)

    def __getstate__(self):
        return self.task

    def __setstate__(self, state: Any):
        match state:
            case (Task() as task):
                pass
            case _:
                assert False, "invalid state type for CRS"
        object.__setattr__(self, '__dict__', self.__class__.from_task(task).__dict__)

    def trigger_tips(self, get_sanitizer_description_available: bool = False):
        if not self.project.harnesses:
            logger.error(f"trigger_tips for {self.project.name} called before harnesses initialized")

        timeout_msg = (
            " and inputs which cause infinite loops or processing times in excess of 5 minutes (not merely slow or "
            "slightly inefficient inputs)"
        )
        if self.project.harnesses and all("timeout_exitcode=0" in h.options for h in self.project.harnesses):
            timeout_msg = ""
        leak_msg = " - note that LeakSanitizer is enabled, so memory leaks will also trigger crashes!"
        if self.project.harnesses and all("detect_leaks=0" in h.options for h in self.project.harnesses):
            leak_msg = ""

        sanitizer_translate = {
            "address": (
                "address sanitizer (ASAN) : alerts on stack, heap, and global out-of-bounds accesses as well as "
                "dynamic memory lifecycle issues (use after free, double free, etc.)" + leak_msg
            ),
            "undefined": (
                "undefined behavior sanitizer (UBSAN) : alerts when performing operations with undefined behavior "
                "(division by zero, out of bounds bitshifts, signed integer overflows, etc). UBSAN is enabled and "
                "configured to immediately abort on error with one exception: *unsigned* integer overflows will not abort. "
                "In other words, *unsigned* integer overflows will only crash if they directly cause a "
                "crashing side effect such as an out-of-bounds access or a SIGSEGV."
            ),
            "memory": "memory sanitizer (MSAN) : alerts when accessing uninitialized memory"
        }

        tips = ""
        match self.project.info.language.lower():
            case "jvm":
                tips += (
                    f"<tip>For the JVM, in addition to unhandled exceptions{timeout_msg}, the default jazzer sanitizers "
                    "are used to identify potential security vulnerabilities. Note that "
                    "Application-specific jazzer security checks may be included in the fuzz harness "
                    "itself or in `@MethodHook`s included with the fuzz harness. These will typically "
                    "raise a jazzer security exception, e.g `FuzzerSecurityIssueHigh`. Keep in mind, "
                    "these sanitizers will cause the program to crash, which is ultimately what determines "
                    "if a PoV is successful.</tip>\n"
                )
                tips += (
                    "<jazzer_sanitizers>\n" +
                    "\n".join(f"<name>{sanitizer}</name>" for sanitizer in BASE_SANITIZERS) +
                    "\n</jazzer_sanitizers>\n"
                )
                if get_sanitizer_description_available:
                    tips += (
                        "<tip>If you need more information about a sanitizer, be sure to call the "
                        "`get_sanitizer_description` tool.</tip>"
                    )
            case "c" | "c++":
                tips += (
                    f"<tip>In addition to inputs that produce uncaught signals (SIGSEGV, SIGILL, SIGABRT, etc){timeout_msg}, "
                    "inputs that trigger enabled Clang sanitizers are also eligible for scoring. The following "
                    "sanitizers are enabled for this project: \n"
                )
                for san in self.project.info.sanitizers:
                    if san in sanitizer_translate: # don't consider introspector, none, etc
                        tips += f"- {sanitizer_translate[san]}\n"
                tips += "</tip>\n"
                tips += (
                    "<IMPORTANT>If you are exploiting a buffer overflow or out-of-bounds "
                    "access, note that the sanitizer will only trigger if you access "
                    "beyond the end of the *allocation*, not just the buffer or array. "
                    "As a result, you may want to use input sizes a bit larger than "
                    "you need to simply overflow the buffer.</IMPORTANT>\n"
                )
            case _: pass
        return tips

    @property
    def harness_paths_str(self):
        assert self.project.harnesses
        return "\n".join(
            [
                f"<harness><num>{i}</num><name>{h.name}</name><source>{h.source}</source></harness>"
                for i, h in enumerate(self.project.harnesses)
            ]
        )
    
    def harness_path_str(self, harness_name: str):
        assert self.project.harnesses
        return "\n".join(
            [
                f"<harness><num>{i}</num><name>{h.name}</name><source>{h.source}</source></harness>"
                for i, h in enumerate(self.project.harnesses) if h.name == harness_name
            ]
        )

    async def is_text_proto_fuzzer(self, harness: Harness):
        if self.project.info.language in {"c", "c++"}:
            source = (await self.searcher.read_full_source(harness.source)).unwrap_or("")
            return "DEFINE_PROTO_FUZZER" in source or "DEFINE_TEXT_PROTO_FUZZER" in source
        return False

    async def harness_tips(
        self,
        harness: Harness
    ) -> str:
        tips = ""
        if await self.is_text_proto_fuzzer(harness):
            tips += (
                "<IMPORTANT>\n"
                "DEFINE_PROTO_FUZZER expects inputs in the protobuf text format. "
                "Here is an example of a proto schema and a sample input in protobuf text format: "
                f"{PROTO_SAMPLE}\n"
                "NOTE: string fields must have *all* special characters escaped. Please include "
                "a note about this in your final output.\n"
                "</IMPORTANT>"
            )
        if self.project.info.language == "jvm":
            match await self.searcher.read_definition("fuzzerTestOneInput", harness.source):
                case Ok(res) if "FuzzedDataProvider" in res["contents"]:
                    tips += (
                        "<IMPORTANT>\n"
                        "It's crucial to understand how `FuzzedDataProvider` consumes bytes from the input buffer. Do NOT simply assume that the order "
                        "of the consume* calls corresponds to the byte order of the data, and do not assume strings must be encoded as fixed-length. "
                        "Here are some useful facts that you MUST keep in mind: "
                        "- `consumeString(N)` consumes bytes from the current *front* of the buffer until either "
                        "`N` bytes are consumed OR a backslash character is found (the character after the backslash is consumed as well). "
                        "To pass a string of length < N, you must terminate it with a backslash followed by an extra throwaway byte.\n"
                        "- `consumeInt` (or any other version of `consumeIntegral`, e.g. `consumeByte`) takes bytes from the current *back* of the buffer.\n"
                        "Rule of thumb: encode strings in the order they are consumed, either terminated with a backslash and a null byte, or "
                        "truncated to the consume length. Encode integral values at the END of the buffer, in reverse of the order that they are "
                        "consumed.\n"
                        "</IMPORTANT>"
                    )
                    # TODO: add information about encoding arrays?
                case _: pass
        return tips

    @property
    def vuln_location_advice(self) -> str:
        return (
            "Here are some examples to help you understand how to identify vulnerability locations:\n"
            "- if a helper function A is being called in a dangerous way by function B, the "
            "vulnerability is in function B.\n"
            "- if a use-after-free is *triggered* in function A due to a dangling reference left by function B, "
            "the vulnerability is in function B.\n"
            "- if the vulnerability is *triggered* in function A, but function B is responsible for sanitizing user "
            "input before passing it to function A, the vulnerability is in function B.\n"
            "- if function B calls function A, and function A allocates a fixed-size buffer and overflows it, "
            "the vulnerability is in function A.\n"
            "Please use the above examples as guidance, but ultimately rely on your reasoning to identify the root cause "
            "for this specific vulnerability.\n"
        )

    async def get_sanitizer_description(self, sanitizer: str) -> Result[SanitizerDescription]:
        d: dict[str, Any] = BASE_SANITIZERS
        if res := d.get(sanitizer):
            return Ok(SanitizerDescription(**res))

        for k, res in d.items():
            if k.lower() == sanitizer.lower():
                return Ok(SanitizerDescription(**res))

        # search through alternates as well
        for k, res in d.items():
            desc = SanitizerDescription(**res)
            for alt in desc.alt:
                if alt.lower() in sanitizer.lower():
                    return Ok(res)

        return Err(CRSError("sanitizer not found", extra={"sanitizers_available": list(d.keys())}))

    def new_fork(self):
        project = self.project.new_fork()
        task = replace(self.task, project=project)
        return self.__class__.from_task(task)
