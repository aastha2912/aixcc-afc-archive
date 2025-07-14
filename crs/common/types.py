from abc import ABC, abstractmethod
from enum import Enum
from crs.common.aio import Path
from typing import Literal, NotRequired, Optional, TypedDict
from uuid import UUID

from pydantic import BaseModel, RootModel, Field
from pydantic.dataclasses import dataclass

from .constants import *
from .core import *

MAX_POV_BLOB_LEN = 2048
# prefer repr if its legnth is <= REPR_INCENTIVE * len(hex)
REPR_INCENTIVE = 1.5


POVLineData = TypedDict('POVLineData', {'content': str, 'count': int})


class BuildConfig(BaseModel):
    SANITIZER: str = DEFAULT_SANITIZER
    ARCHITECTURE: str = DEFAULT_ARCHITECTURE
    FUZZING_LANGUAGE: str = DEFAULT_LANGUAGE
    FUZZING_ENGINE: str = DEFAULT_ENGINE
    CFLAGS: str = ""

    def __str__(self):
        return "_".join([
            self.FUZZING_LANGUAGE,
            self.SANITIZER,
            self.ARCHITECTURE,
            self.FUZZING_ENGINE,
            self.CFLAGS.replace(" ", "_"),
        ])

    def __hash__(self):
        return hash(str(self))

    def to_dict(self):
        return super().model_dump() | {"CXXFLAGS": self.CFLAGS}

class PatchArtifact(BaseModel):
    build_tar_path: str
    build_config: BuildConfig

class POVOutputData(TypedDict):
    note: NotRequired[str]
    captured_lines: list[POVLineData]
    status: str

class FoundLocation(BaseModel):
    func: str
    file: str
    line: int

DefinitionType = Literal["#define", "typedef", "function", "reference", "unknown"]
@dataclass(slots=True)
class FileDefinition:
    line: int
    content: Optional[str]
    type: DefinitionType

class LineDefinition(BaseModel):
    line: int
    name: str

class LineHitDict(TypedDict):
    file: str
    line: int

class FileDefinitions(BaseModel):
    file_name: str
    defs: list[FileDefinition]

class FileReference(BaseModel):
    line: int
    content: Optional[str]
    enclosing_definition: str

class FileReferences(BaseModel):
    file_name: str
    refs: list[FileReference]

class SourceDefSite(BaseModel):
    name: str
    mangled_name: str
    begin: int
    end: int
    qual_type: str

ErrorDict = TypedDict('ErrorDict', {'error': str})

class DefinitionSite(TypedDict):
    file: Path
    start: int
    end: int
    code: NotRequired[str]

class SourceContents(TypedDict):
    contents: str
    line_start: int
    line_end: int

class CallDef(BaseModel):
    caller: str
    file: str
    line: int
    content: str

class CompileCommand(BaseModel):
    directory: str
    arguments: list[str]
    file: str

class CompileCommands(RootModel[list[CompileCommand]]):
    pass

class POVTarget(BaseModel):
    task_uuid: UUID
    project_name: str
    harness: str
    sanitizer: str
    engine: str

class POVRunData(POVTarget):
    python: Optional[str]
    input: bytes
    output: str
    dedup: str
    stack: str

    def safe_decode(self) -> 'DecodedPOV':
        if self.python:
            return DecodedPOV.create(self, decoding=f"<pov_script>\n{self.python}\n</pov_script>\n")
        # we have no decoder, so use either hex or repr, whichever is shorter
        pov_blob = self.input[:MAX_POV_BLOB_LEN]
        hexd = f"<pov_hex>{pov_blob.hex()}</pov_hex>\n"
        reprd = f"<pov_repr>{repr(pov_blob)}</pov_repr>\n"
        decoding = hexd if REPR_INCENTIVE * len(hexd) < len(reprd) else reprd
        if len(self.input) > MAX_POV_BLOB_LEN:
            decoding += f"<note>pov_blob was truncated because it was too long</note>\n"
        return DecodedPOV.create(self, decoding)

    async def decode(self, decoder: 'Decoder', try_keep_raw: bool = False) -> Result['DecodedPOV']:
        match await decoder.decode_all({"pov": self.input}):
            case Ok(results):
                raw = ""
                if try_keep_raw and len(self.input) < MAX_POV_BLOB_LEN:
                    hexd = f"<pov_hex>{self.input.hex()}</pov_hex>\n"
                    reprd = f"<pov_repr>{repr(self.input)}</pov_repr>\n"
                    raw = hexd if len(hexd) < len(reprd) else reprd
                return Ok(DecodedPOV.create(self, decoding=(
                    f"<decoding>\n"
                    f"{raw}"
                    f"<decoder_type>{type(decoder).__name__}</decoder_type>\n"
                    f"<decoded>\n{results["pov"]}\n</decoded>\n"
                    "</decoding>\n"
                )))
            case Err() as e:
                return e

class POVRes(POVRunData):
    vuln_id: Optional[int] = None

class DecodedPOV(POVRunData):
    decoding: str

    @staticmethod
    def create(pov: POVRunData, decoding: str):
        return DecodedPOV(**pov.model_dump(), decoding=decoding)

    def as_pretty_xml(self, include_output: bool = True):
        res = "<pov>\n"
        res += f"<harness>{self.harness}</harness>\n"
        res += f"<input_length>{len(self.input)}</input_length>\n"
        if include_output:
            res += f"<pov_output>\n{trim_tool_output(self.output, ratio=1)}</pov_output>\n"
        res += self.decoding
        res += f"</pov>\n"
        return res

class AnalyzedVuln(BaseModel):
    function: str = Field(description=(
        "the function which contains the root cause of the vulnerability - if java, only use the method name and omit the class name"
    ))
    file: str = Field(description=(
        "the file containing the vulnerable function"
    ))
    description: str = Field(description=(
        "a brief description of the root cause of the vulnerability - if the root cause stems from a different function "
        "than the one which is vulnerable to crash, please include the location of crash as well"
    ))
    conditions: str = Field(description=(
        "a brief description of conditions required to trigger the vulnerability - this should include "
        "an overview of the data flow from the harness and any constraints on the input required to "
        "trigger a crash"
    ))

    def format(self):
        return (
            f"Vulnerability in {self.function} in {self.file}:\n"
            f"{self.description}\nTrigger conditions: {self.conditions}"
        )

class VulnReport(BaseModel):
    task_uuid: UUID
    project_name: str
    function: str
    file: str
    description: str
    source: Optional[str] = None
    sarif_id: Optional[UUID] = None
    function_range: Optional[tuple[int, int]] = None

    def format_xml(self):
        return (
            f"<report>\n"
            f"<function>{self.function}</function>\n"
            f"<file>{self.file}</file>\n"
            f"<description>\n"
            f"{self.description}\n"
            f"</description>\n"
            f"</report>"
        )


class PatchRes(BaseModel):
    task_uuid: UUID
    project_name: str
    diff: str
    vuln_id: int
    artifacts: list[PatchArtifact]

class Priority(float, Enum):
    LOWEST = float('inf')
    LOW = 100
    MEDIUM = 10
    HIGH = 1
    CRITICAL = 0

DEFAULT_DECODER_TIMEOUT = 60

class Decoder(ABC, BaseModel):
    @abstractmethod
    def decode_all(
        self,
        corpus: dict[str, bytes],
        timeout: float = DEFAULT_DECODER_TIMEOUT,
        trim_output: bool = False
    ) -> Coro[Result[dict[str, str]]]:
        ...

    @abstractmethod
    def format(self) -> str:
        ...