#!/bin/bash

(cd curl && git reset --hard 75a2079d5c28debb2eaa848ca9430f1fe0d7844c)  # tag:8.11.1
(cd curl_fuzzer && git reset --hard 24f27bd32b4f51a75256c413c6366a0befbec8ce)

for commit in $(ls commits/); do
  (
    cd curl && \
    git apply --index ../commits/$commit && \
    git -c user.name="Theori" -c user.email="aixcc@theori.io" commit -m "apply $commit"
  )
done
