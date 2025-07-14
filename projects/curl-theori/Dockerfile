# Copyright 2016 Google Inc.
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

FROM ghcr.io/aixcc-finals/base-builder:v1.3.0

RUN git clone --no-checkout https://github.com/curl/curl.git $SRC/curl && \
    cd $SRC/curl && git fetch --tags && git checkout curl-8_11_1
RUN git clone https://github.com/curl/curl-fuzzer.git $SRC/curl_fuzzer

# Use curl-fuzzer's scripts to get latest dependencies.
RUN $SRC/curl_fuzzer/scripts/ossfuzzdeps.sh

# Apply our theori-specific commits
COPY commits/ $SRC/commits
COPY apply_commits.sh $SRC/
RUN $SRC/apply_commits.sh

WORKDIR $SRC/curl
COPY build.sh $SRC/

RUN sed -i 's/enable-ssl3-method /enable-ssl3-method no-tests /' "$SRC/curl_fuzzer/scripts/install_openssl.sh"

RUN sed -i 's/-j$(nproc)/-j$(( $(nproc) < 16 ? $(nproc) : 16 ))/' "$SRC/curl_fuzzer/ossfuzz.sh"
