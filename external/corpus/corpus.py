#!/usr/bin/env python3
from hashlib import sha1
import json
from multiprocessing import Pool
from pathlib import Path
import random
import re
import requests
import shutil
import subprocess
import tempfile
from tqdm import tqdm
from typing import Optional
import zipfile

hash_re = re.compile("[0-9a-f]{64}")

url = "https://storage.googleapis.com/{proj}-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/{proj}_{harness}/public.zip"
git_corpuses = [
    "https://github.com/strongcourage/fuzzing-corpus",
    "https://github.com/dvyukov/go-fuzz-corpus",
]

sample_dir = Path("sample")
archive_dir = Path("corpus")
downloaded_dir = Path("seeds")

def download(proj: str, harness: str):
    output_path = downloaded_dir / proj / f"{harness}.zip"
    if output_path.exists():
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with requests.get(url.format(proj=proj, harness=harness), stream=True) as r:
            r.raise_for_status()
            with open(output_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:  # filter out keep-alive chunks
                        _ = f.write(chunk)
        return True
    except requests.HTTPError:
        return False

def handle_zip(proj: str, kind: str, zippath: Path):
    z = zipfile.ZipFile(zippath)
    if all(zi.file_size < 3 for zi in z.infolist()):
        # this is junk, ignore it
        return
    with tempfile.TemporaryDirectory(dir="/dev/shm/") as td:
        (archive_dir / proj).mkdir(parents=True, exist_ok=True)
        if (archive_dir / proj / f"{kind}.tar.xz").exists():
            return
        outpath = Path(td, proj, kind)
        outpath.mkdir(parents=True, exist_ok=True)
        for zi in z.infolist():
            if zi.is_dir():
                continue
            if zi.file_size < 2:
                continue
            # this is our max submittable pov length
            if zi.file_size > 2*1024*1024:
                continue
            name = Path(zi.filename).stem
            dat = z.open(zi.filename).read()
            if not hash_re.match(name):
                # hash to get a unique name
                name = sha1(dat).hexdigest()
            _ = open(Path(td) / proj / kind / name, "wb").write(dat)

        # select [up to] 10 files at random. Weed out "trivial" files
        random.seed(proj + kind)
        population = sorted([x for x in outpath.iterdir() if 40 < (outpath/x).stat().st_size < 128*1024])
        sampled = random.sample(population, min(10, len(population)))
        for s in sampled:
            shutil.copy(s, sample_dir / s.name[0] / f"{proj}__{kind}__{s.name}")
        _ = subprocess.check_call(["tar", "-I", "xz -9", "-cf", archive_dir / proj / f"{kind}.tar.xz", "-C", outpath.as_posix(), "."])

def handle_folder(collection: str, kind: str, folder: Path):
    with tempfile.TemporaryDirectory() as td:
        population: list[str] = []
        for root, _, sub in folder.walk():
            for child in sub:
                p = root/child
                sz = p.stat().st_size
                if not (2 < sz < 2*1024*1024):
                    continue
                sha = sha1(p.read_bytes()).hexdigest()
                shutil.copy(p, f"{td}/{sha}")
                if 40 < sz < 128*1024:
                    population.append(f"{td}/{sha}")

        (archive_dir / collection).mkdir(parents=True, exist_ok=True)
        _ = subprocess.check_call(["tar", "-I", "xz -9", "-cf", archive_dir / collection / f"{kind}.tar.xz", "-C", td, "."])

        sampled = random.sample(population, min(10, len(population)))
        for ss in sampled:
            s = Path(ss)
            shutil.copy(s, sample_dir / s.name[0] / f"{collection}__{kind}__{s.name}")


def repackage(f: Path, unzip: bool=False):
    """
    Go through given folder to search for seeds. Each folder (or zip if unzip is set) is assumed to be
    an equivalence class of seeds
    """
    wait = []
    with Pool(processes=8) as pool:
        last_folder: Optional[str] = None
        for root, _, sub in f.walk():
            if not unzip:
                if root.relative_to(f).parts and root.relative_to(f).parts[0] != last_folder:
                    last_folder = root.relative_to(f).parts[0]
                    if last_folder == ".git":
                        continue
                    wait.append(
                        pool.apply_async(handle_folder, [f.name, last_folder, root])
                    )
            else:
                for child in sub:
                    child_path = root / child
                    if child_path.suffix == ".zip":
                        wait.append(
                            pool.apply_async(handle_zip, [child_path.parent.name, child_path.stem, child_path])
                        )

        for res in tqdm(wait):
            res.wait()
            res.successful()

if __name__ == "__main__":
    for c in "abcdef0123456789":
        (sample_dir / c).mkdir(parents=True, exist_ok=True)
    for i in range(256):
        # just to make sure trivial cases are covered by corpus data, write all single bytes
        _ = (sample_dir / "abcdef0123456789"[i%16] / str(i)).write_bytes(bytes([i]))

    to_grab = json.load(open("clusterfuzz.json"))
    print("downloading")
    for p, h in tqdm(to_grab):
        _ = download(p, h)
    repackage(downloaded_dir, unzip=True)

    for i, c in enumerate(git_corpuses):
        _ = subprocess.check_call(["git", "clone", "--depth", "1", c, f"c{i}"])
        repackage(Path(f"c{i}"))

    _ = subprocess.check_call(["tar", "-I", "xz -9", "-cf",  f"sample.tar.xz", "-C", sample_dir.as_posix(), "."])
