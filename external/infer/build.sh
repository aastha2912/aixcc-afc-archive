#!/bin/bash -eux

basedir=$(cd "$(dirname "$0")" && pwd)
commit_hash=$(git rev-parse --short HEAD)
docker build -t "infer:$commit_hash" "$basedir"

docker run --rm "infer:$commit_hash" \
       tar -cJf - \
       --exclude infer/bin/infer.exe \
       --exclude .gitignore \
       infer/bin \
       infer/lib \
       facebook-clang-plugins \
       >"infer_${commit_hash}.tar.xz"
