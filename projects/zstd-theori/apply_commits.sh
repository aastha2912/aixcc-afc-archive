#!/bin/bash

(cd zstd && git reset --hard f229daaf428ac4f847c79fd615d97a0e1820267a)

for commit in $(ls commits/); do
  (
    cd zstd && \
    git apply --index ../commits/$commit && \
    git -c user.name="Theori" -c user.email="aixcc@theori.io" commit -m "apply $commit"
  )
done
