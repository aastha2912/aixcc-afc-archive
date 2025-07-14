from pathlib import Path
from typing import Optional
import argparse
import asyncio
import json
import os
import re

DEFAULT_FUZZER_DIRS = ["aflplusplus", "fuzztest", "libfuzzer", "honggfuzz", "libprotobuf-mutator"]

VALID_TARGET_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
BLOCKLISTED_TARGET_NAME_REGEX = re.compile(r'^(jazzer_driver.*)$')
FUZZ_TARGET_SEARCH_BYTES = b'LLVMFuzzerTestOneInput'
ALLOWED_FUZZ_TARGET_EXTENSIONS = ['', '.exe']

async def ripgrep(pattern: str, path: Path, ftypes: Optional[list[str]] = None) -> list[str]:
    extra_args: list[str] = []
    if ftypes:
        for ftype in ftypes:
            extra_args.append("-t")
            extra_args.append(ftype)

    process = await asyncio.create_subprocess_exec(
        "rg", "--files-with-matches", *extra_args, pattern, path.as_posix(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()

    if process.returncode not in (0, 1):  # 0 means matches found, 1 means no matches
        raise RuntimeError(f"Ripgrep failed with error: {stderr.decode(errors="replace").strip()}")

    # Decode and split the output into filenames
    return stdout.decode(errors="replace").splitlines()

def is_valid_fuzz_target(path: Path) -> bool:
    basename = path.name
    if not VALID_TARGET_NAME_REGEX.match(basename):
        return False
    if BLOCKLISTED_TARGET_NAME_REGEX.match(basename):
        return False
    _, extension = os.path.splitext(basename)
    if extension not in ALLOWED_FUZZ_TARGET_EXTENSIONS:
        return False 
    if not os.access(path, os.X_OK):
        return False
    if basename.endswith("_fuzzer"):
        return True
    if not path.is_file():
        return False
    return FUZZ_TARGET_SEARCH_BYTES in path.read_bytes()

def extract_matching_strings(buf: bytes, target: str) -> set[str]:
    matches: set[str] = set()
    offset = 0
    while True:
        offset = buf.find(target.encode(), offset)
        if offset == -1:
            break

        start = offset - 1
        end = offset + len(target)
        for start in range(offset-1, offset - 4096, -1):
            if buf[start] == 0:
                break
        for end in range(offset + len(target), offset + len(target) + 4096):
            if buf[end] == 0:
                break
        matches.add( buf[start+1:end].decode(errors="ignore") )
        offset += 1 
    return matches

def path_match_count(src: str, target: str) -> float:
    target_components = os.path.normpath(target).split("/")[::-1]
    src_components = os.path.normpath(src).split("/")[::-1]
    if src == target: 
        return len(src_components) + 1
    for i in range(min(len(src_components), len(target_components)), 1, -1):
        if src_components[:i] == target_components[:i]:
            # tie breaker: if 4 path components match, but the path had 30, it's
            # probably not as good as 4 path components matching with 10 total
            return i - len(src_components)/20
    return 0

async def heuristic_harness_match(language: str, out_path: Path, src_path: Path) -> dict[str, set[str]]:
    harness_bins: list[str] = []
    for path in out_path.iterdir():
        if is_valid_fuzz_target(path):
            harness_bins.append(path.name)

    harness_matches: dict[str, set[tuple[str, float]]] = {h: set() for h in harness_bins}

    # find eligible files with the necessary strings to be fuzzer harness sources
    pattern_dict: dict[str, tuple[list[str], list[str]]] = {
        "rust": (["rust"], ["libfuzzer_sys::"]),
        "c": (["c", "cpp"], ["LLVMFuzzerTestOneInput", "DEFINE_PROTO_FUZZER"]),
        "c++": (["c", "cpp"], ["LLVMFuzzerTestOneInput", "DEFINE_PROTO_FUZZER"]),
        "jvm": (["java", "kotlin", "scala"], ["FuzzTest", "fuzzerTestOneInput"]),
        "python": (["py"], ["def TestOneInput", "atheris.Fuzz()"]),
    }

    try:
        langs, patterns = pattern_dict[language]
    except KeyError:
        raise KeyError(f"unsupported language: {language}") from None

    eligible_src: set[str] = set()
    tasks = [ripgrep(pattern, src_path, ftypes=langs) for pattern in patterns]
    for rg_matches in await asyncio.gather(*tasks):
        eligible_src |= set(os.path.relpath(p, src_path) for p in rg_matches)

    ignore: set[str] = set()
    for eligible in eligible_src:
        if any(eligible.startswith(fuzzer_dir) for fuzzer_dir in DEFAULT_FUZZER_DIRS):
            ignore.add(eligible)
    eligible_src -= ignore

    # 1 binary and 1 source file? shipit
    if len(harness_bins) == 1 and len(eligible_src) == 1:
        return {harness_bins[0]: eligible_src}

    if language in {"rust", "c", "c++"}:
        # find the source file that is referenced in the debug metadata info
        for h in harness_bins:
            bin_data = (out_path / h).read_bytes()
            for src in eligible_src:
                extra = "/@" if language == "rust" else ""
                matches = extract_matching_strings(bin_data, os.path.basename(src) + extra)
                if not matches:
                    continue
                top_score = max([path_match_count(Path(src).as_posix(), m) for m in matches])
                harness_matches[h].add((src, top_score))

    elif language == "jvm":
        # find the source file that defines the class used in the harness
        class_match = re.compile(r"--target_class=(\S+)")
        for h in harness_bins:
            bin_data = (out_path / h).read_bytes()
            match = class_match.search(bin_data.decode(errors="ignore"))
            if match:
                class_name, = match.groups()
                class_name = class_name.split(".")[-1]
                for src in eligible_src:
                    if (f"class {class_name}").encode() in (src_path / src).read_bytes():
                        harness_matches[h].add((src, 1))

    elif language == "python":
        # find the source file which has a matching name to the harness
        for h in harness_bins:
            for src in eligible_src:
                if os.path.basename(h) in src:
                    harness_matches[h].add((src, 1))

    # if there are multiple plausible matches, source file names match the
    # harness name, then filter down to those
    def best_harness_match(harness_name: str, potentials: set[tuple[str, float]]):
        if len(potentials) == 1:
            return set(x for x,_ in potentials)
        name_matches: set[tuple[str, float]] = set()
        target_name = os.path.basename(harness_name)
        best_score = 0.
        for source, score in potentials:
            if target_name in os.path.basename(source):
                name_matches.add((source, score))
        if name_matches:
            potentials = name_matches
        best_score = max([y for _, y in potentials]) if potentials else 0.
        return set(x for x,y in potentials if y == best_score)

    return {k: best_harness_match(os.path.basename(k), v) for k, v in harness_matches.items()}

async def main() -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("language")
    _ = parser.add_argument("--src", default="/src")
    _ = parser.add_argument("--out", default="/out")
    args = parser.parse_args()

    results = await heuristic_harness_match(
        language=args.language,
        src_path=Path(args.src),
        out_path=Path(args.out),
    )
    print(json.dumps({k: list(v) for k, v in results.items()}))

if __name__ == "__main__":
    asyncio.run(main())
