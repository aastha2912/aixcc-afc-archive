import re

from itertools import zip_longest
from typing import Generator, Protocol, Tuple

GIT_HEADER_RE = re.compile(r"^diff --git (.+) (.+)$", flags=re.MULTILINE)

def strip_path(path: str):
    return path[2:] if path[:2] in {"a/", "b/"} else path

def iter_sections(diff: str) -> Generator[Tuple[str, str, str], None, None]:
    matches = list(GIT_HEADER_RE.finditer(diff))
    for match, next in zip_longest(matches, matches[1:]):
        end = next.start() if next is not None else len(diff)
        start = match.start()
        prev, post = map(strip_path, match.groups())
        yield (diff[start:end], prev, post)

class DiffSectionFilter(Protocol):
    def __call__(self, section: str, prev: str, post: str) -> str | None:
        ...

def filter_diff(diff: str, filter: DiffSectionFilter):
    return "".join(
        res for section, prev, post in iter_sections(diff) if (res := filter(section, prev, post))
    )

def iter_prev_paths(diff: str) -> Generator[str, None, None]:
    for match in GIT_HEADER_RE.finditer(diff):
        yield strip_path(match.groups()[0])

def iter_post_paths(diff: str) -> Generator[str, None, None]:
    for match in GIT_HEADER_RE.finditer(diff):
        yield strip_path(match.groups()[1])