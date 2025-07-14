#!/usr/bin/env python3
"""
dedup_mon.py : follow a growing log file, correlate DEDUP_TOKEN lines
with libFuzzer crash-file messages, and drop marker files that encode a
deduplication hash.

Usage:
    python dedup_mon.py /path/to/logfile
Press Ctrl-C to stop.
"""
import argparse
import hashlib
import os
import re
import time

PAT_DEDUP   = re.compile(r"DEDUP_TOKEN: (.*)")
PAT_ARTIFACT = re.compile(
    r"artifact_prefix='.*'; Test unit written to (.+/crash-[0-9a-f]{40})"
)

def follow(fname: str, poll_ms: float = 100):
    """
    Yield new lines appended to *fname*
    If the file is truncated or rotated, reopen it automatically.
    Uses simple polling
    """
    inode = None
    fp = None
    offset = 0

    while True:  # run forever
        try:
            st = os.stat(fname)
        except FileNotFoundError:
            time.sleep(poll_ms / 1000)
            continue

        # (re)open if first loop, rotation, or truncation
        if fp is None or st.st_ino != inode:
            if fp:
                fp.close()
            fp = open(fname, "r", encoding="utf-8", errors="replace")
            inode = st.st_ino
            offset = 0

        # seek to previous position if the file was truncated
        if st.st_size < offset:
            fp.seek(0)
            offset = 0

        # read any new lines
        fp.seek(offset)
        chunk = fp.read()
        offset = fp.tell()

        if chunk:
            yield from chunk.splitlines()

        time.sleep(poll_ms / 1000.0)


def main(log_path: str):
    token_buf: list[str] = []

    for line in follow(log_path):
        # collect dedup tokens
        if m1 := PAT_DEDUP.search(line):
            token_buf.append(m1.group(1))
            continue

        # on crash file message
        if m2 := PAT_ARTIFACT.search(line):
            if not token_buf: # no known dedupe tokens, ignore
                continue

            digest = hashlib.sha1("".join(token_buf).encode()).hexdigest()
            target_path = f"{m2.group(1)}.{digest}"

            try:
                # create a marker file; overwrite if it exists
                open(target_path, "wb").close()
                print(f"[+] wrote marker: {target_path}")
            except OSError as e:
                print(f"[!] could not create {target_path}: {e}")
            token_buf.clear()

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Log follower for DEDUP_TOKEN + crash correlation")
    ap.add_argument("logfile", help="Path to the log file to follow")
    args = ap.parse_args()

    try:
        main(args.logfile)
    except KeyboardInterrupt:
        print("\n[+] stopping.")
