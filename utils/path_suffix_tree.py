#!/usr/bin/env python3
import json
import sys
from pathlib import Path

PathSuffixDict = dict[str, 'PathSuffixDict']

def _build_path_suffix_tree(root: Path) -> PathSuffixDict:
    assert root.is_dir()
    result: PathSuffixDict = {}
    visited: set[str] = set()
    def add_file(path: Path):
        path = path.relative_to(root)
        cur = result
        for part in path.parts[::-1]:
            if part not in cur:
                cur[part] = {}
            cur = cur[part]

    def helper(dir: Path):
        dir = dir.resolve()
        if dir.as_posix() in visited:
            return
        visited.add(dir.as_posix())
        for f in dir.iterdir():
            if f.is_file():
                add_file(f)
            elif f.is_dir():
                helper(f)

    helper(root)
    return result

if __name__ == "__main__":
    print(json.dumps(_build_path_suffix_tree(Path(sys.argv[1]))))