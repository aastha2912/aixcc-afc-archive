#!/bin/bash
set -ex

cd "$(dirname "$0")"

make -C external/bear

# build utils
make -C utils/wrapper_engine/
make -C utils/jacoco_parser/
make -C utils/lcov_parser/