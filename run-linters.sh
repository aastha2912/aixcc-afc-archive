#!/usr/bin/env bash

FAIL=0

python -m ruff check || FAIL=1

# TODO: use .flake8 config file for more options, but
#   1. it doesn't support pyproject
#   2. its config parsing raised validation errors because issues like ASYNCXXX are 'invalid' ?
python -m flake8 --select=ASYNC,CRS --ignore=ASYNC240,ASYNC910,ASYNC911,ASYNC121,ASYNC124,ASYNC109 crs || FAIL=1

exit $FAIL