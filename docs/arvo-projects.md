# Selected OSS-Fuzz crashes from the ARVO dataset

From the ARVO dataset: https://github.com/n132/ARVO-Meta

The contents described in this file can be found at `tests/app/tasks/arvo-tasks/`.

Each projects in this list contains:
- A specific commit of a project where at least one oss-fuzz crash exists
- A built docker image at that point - therefore a crashable input is guaranteed to exist.
    - Dependencies such as oss-fuzz are also reverted to the past.
    - ARVO does provide a docker image, but not the Dockerfile nor scripts to reproduce that state. Each image can be found at `https://hub.docker.com/r/n132/arvo/tags?name=[crash-id]-vul`, and this is what we pull to create a task environment.
- Link to the oss-fuzz crash report
- Link to the patch commit diff (provided by ARVO)

Note: Each task contains "a" bug (provided by the ARVO dataset), but the task may have other crashes too (e.g. The `pcre2` task was created using crash id [61269](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=61269), but crash id [61268](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=61268) can also happen in that commit.)

## Projects
- miniz / use of uninitialized value / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=44477) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/44477.diff)
- libplist / heap read overflow / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=54948) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/54948.diff)
- pcre2 / heap write overflow / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=61269) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/61269.diff)
- jq / segv on unknown address / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=61050) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/61050.diff)
- usrsctp / global write overflow / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47712) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/47712.diff)
- lz4 / invalid free / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=48884) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/48884.diff)
- opensc / stack read overflow / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=64522) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/64522.diff)
- tmux / index out-of-bounds [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=47933) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/47933.diff)
- gpsd / use-after-poison / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=52037) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/52037.diff)
- mruby / unknown write / [\[report link\]](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=48904) [\[patch diff\]](https://github.com/n132/ARVO-Meta/blob/main/patches/48904.diff)
