## Copyright 2016 Google Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
#################################################################################
#
#FROM ghcr.io/aixcc-finals/base-builder:v1.1.0
#RUN apt-get update && apt-get install -y make autoconf automake libtool curl tcl zlib1g-dev tcl-dev
#
## We won't be able to poll fossil for changes, so this will build
## only once a day.
#RUN mkdir $SRC/sqlite3 && \
#    cd $SRC/sqlite3 && \
#    curl 'https://www.sqlite.org/src/tarball?uuid=trunk' -o sqlite3.tar.gz && \
#    tar xzf sqlite3.tar.gz
#
#RUN find $SRC/sqlite3 -name "*.test" | xargs zip $SRC/ossfuzz_seed_corpus.zip
#
#WORKDIR sqlite3
#COPY build.sh *.dict *.options $SRC/

FROM pull.chameleon.aixcc.tech/afc-54ab894b-64b5-4fea-9b6c-f62390c07469:9269fdc1-86e5-43f4-9a76-c6b4a809a056

# clone private repo via a deploy key
RUN rm -rf $SRC/sqlite3
COPY deploy_key $SRC/deploy_key
RUN chmod 600 $SRC/deploy_key
RUN GIT_SSH_COMMAND="ssh -i $SRC/deploy_key -o StrictHostKeyChecking=no" git clone -b theori-eval/sq-delta-01 git@github.com:theori-io/afc-sqlite3.git $SRC/sqlite3
WORKDIR $SRC/sqlite3
