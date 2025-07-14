#!/bin/bash -eu
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
git apply $SRC/add_fuzzers.diff

cp -r $SRC/fuzz src/
cp $SRC/make_fuzzers auto/make_fuzzers

cd src/fuzz
rm -rf genfiles && mkdir genfiles && $SRC/LPM/external.protobuf/bin/protoc http_request_proto.proto --cpp_out=genfiles
cd ../..

auto/configure \
    --with-ld-opt="-Wl,--wrap=writev -Wl,--wrap=getsockopt -Wl,--wrap=select -Wl,--wrap=recv -Wl,--wrap=read -Wl,--wrap=send -Wl,--wrap=epoll_create -Wl,--wrap=epoll_create1 -Wl,--wrap=epoll_wait -Wl,--wrap=epoll_ctl -Wl,--wrap=close -Wl,--wrap=ioctl -Wl,--wrap=listen -Wl,--wrap=accept -Wl,--wrap=accept4 -Wl,--wrap=setsockopt -Wl,--wrap=bind -Wl,--wrap=shutdown -Wl,--wrap=connect -Wl,--wrap=getpwnam -Wl,--wrap=getgrnam -Wl,--wrap=chmod -Wl,--wrap=chown" \
    --with-cc-opt='-DNGX_DEBUG_PALLOC=1' \
    --with-http_v2_module \
    --with-mail
make -f objs/Makefile fuzzers

cp objs/*_harness objs/*_fuzzer $OUT/
cp $SRC/fuzz/*.dict $OUT/
mkdir ${OUT}/html
cp ${SRC}/nginx/docs/html/index.html ${OUT}/html/index.html

for harness in "http_request_fuzzer" "mail_request_harness" "smtp_harness"; do
    echo "[asan]" > ${OUT}/$harness.options
    echo "detect_leaks=0" >> ${OUT}/$harness.options
done

mkdir ${OUT}/logs/