# TODO: should use preprocessed code? probably.
#       TODO: how do we represent a preprocessed and unpreprocessed view of the same file?
# TODO: where do annotations go? do they live inside SourceFile?
# what about line-level annotations?
# TODO: can we capture call graph in here somehow? networkx?
# TODO: graph of scope / declaration hierarchy, separate from call graph scope

# can i just flatten everything out? so it's defs, and they say which file they came from but it's just a global list of things.
# what about grouping different types of defs?

from dataclasses import dataclass, field
from typing import Self
import bisect

import tree_sitter

@dataclass(slots=True, frozen=True)
class SourceRange:
    a: int
    b: int

    @classmethod
    def from_node(cls, node: tree_sitter.Node) -> Self:
        return cls(*node.byte_range)

    def contains_range(self, other: Self) -> bool:
        return self.a <= other.a and self.b >= other.b

def node_range(node: tree_sitter.Node) -> SourceRange:
    return SourceRange.from_node(node)

@dataclass(slots=True, frozen=True)
class SourceMember:
    name: bytes
    fullname: bytes
    file: "SourceFile" = field(repr=False)
    range: SourceRange

@dataclass(slots=True, frozen=True)
class SourceFunction(SourceMember):
    sig: SourceRange
    args: SourceRange
    return_type: SourceRange
    body: SourceRange

@dataclass(slots=True, frozen=True)
class SourceClass(SourceMember):
    body: SourceRange

@dataclass(slots=True, frozen=True)
class SourceFile:
    path: str
    source: bytes
    line_index: tuple[int] = field(default_factory=tuple[int], repr=False)

    def __post_init__(self):
        index: list[int] = []
        acc = 0
        index.append(0)
        for line in self.source.splitlines(keepends=True):
            acc += len(line)
            index.append(acc)
        object.__setattr__(self, 'line_index', tuple(index))

    def __getitem__(self, idx: slice | SourceRange) -> bytes:
        if isinstance(idx, SourceRange):
            return self.source[idx.a:idx.b]
        return self.source[idx]

    def offset_to_line(self, off: int) -> int:
        idx = bisect.bisect_right(self.line_index, off) - 1
        if idx < 0 or idx >= len(self.line_index):
            raise IndexError(off)
        return idx

    def expand_range_to_lines(self, range: SourceRange) -> SourceRange:
        lineno = self.offset_to_line(range.a)
        a = self.line_index[lineno]
        return SourceRange(a, range.b)

    def range_to_lines(self, range: SourceRange) -> tuple[int, int]:
        return (self.offset_to_line(range.a), self.offset_to_line(range.b))

    def line_to_range(self, line: int) -> SourceRange:
        a, b = self.line_index[line:line+2]
        return SourceRange(a, b)

@dataclass(slots=True)
class AnalysisProject:
    files: dict[str, SourceFile] = field(default_factory=dict[str, SourceFile])
    decls: list[SourceMember] = field(default_factory=list[SourceMember])
    name_to_decl: dict[bytes, SourceMember] = field(default_factory=dict[bytes, SourceMember])

    def build_lut(self) -> None:
        for decl in self.decls:
            self.name_to_decl[decl.name] = decl

@dataclass(slots=True)
class Report:
    actions: list[str] = field(default_factory=list[str])
    summary: str = ""
    sinks: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    vulns: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    invariants: list[dict[str, str]] = field(default_factory=list[dict[str, str]])

@dataclass(slots=True)
class MultiVuln:
    name: str = ""
    found: bool = False
    functions: list[dict[str, str]] = field(default_factory=list[dict[str, str]])

@dataclass(slots=True)
class MultiReport:
    summary: str = ""
    sinks: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    vulns: list[MultiVuln] = field(default_factory=list[MultiVuln])

@dataclass(slots=True)
class AnnotatedReport:
    member: SourceMember
    report: Report | MultiReport
    vulns: list[str]
