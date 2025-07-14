#!/bin/bash -eu

sed -i 's/--with-libpng-prefix=[^[:space:]]*/--with-libpng-prefix=/' /src/build.sh
export PATH=/opt:$PATH

exec compile
