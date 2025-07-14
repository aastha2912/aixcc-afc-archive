#!/bin/bash

if [[ -z "${FUZZER}" ]]; then
    echo "Error: FUZZER is not defined." >&2
    exit 1
fi

OPTIONS_FILE="$OUT/$FUZZER.options"

if [ -f $OPTIONS_FILE ]; then
  custom_asan_options=$(parse_options.py $OPTIONS_FILE asan)
  if [ ! -z $custom_asan_options ]; then
    export ASAN_OPTIONS="$ASAN_OPTIONS:$custom_asan_options"
  fi

  custom_msan_options=$(parse_options.py $OPTIONS_FILE msan)
  if [ ! -z $custom_msan_options ]; then
    export MSAN_OPTIONS="$MSAN_OPTIONS:$custom_msan_options"
  fi

  custom_ubsan_options=$(parse_options.py $OPTIONS_FILE ubsan)
  if [ ! -z $custom_ubsan_options ]; then
    export UBSAN_OPTIONS="$UBSAN_OPTIONS:$custom_ubsan_options"
  fi

  CUSTOM_LIBFUZZER_OPTIONS=$(parse_options.py $OPTIONS_FILE libfuzzer)
fi