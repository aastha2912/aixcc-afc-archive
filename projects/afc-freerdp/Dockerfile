## Copyright 2023 Google LLC
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
#
## See https://github.com/FreeRDP/FreeRDP/wiki/Compilation
## Install Git and base dependences.
#RUN apt-get update && apt-get install -y devscripts equivs \
#	build-essential git-core cmake ninja-build pkg-config ccache
#
#RUN git clone --depth 1 https://github.com/FreeRDP/FreeRDP.git
#
#WORKDIR FreeRDP
#
## Install all dependencies required by the nightly package.
#RUN mk-build-deps --install --tool 'apt-get --yes --no-remove --no-install-recommends' packaging/deb/freerdp-nightly/control
#
#COPY build.sh *.options $SRC/

FROM pull.chameleon.aixcc.tech/afc-eedf06e3-2344-442d-b863-98289a724c7d:cb3953dc-cc66-4f16-b999-0a04b4f0e573

# clone private repo via a deploy key
RUN rm -rf $SRC/FreeRDP
COPY deploy_key $SRC/deploy_key
RUN chmod 600 $SRC/deploy_key
RUN GIT_SSH_COMMAND="ssh -i $SRC/deploy_key -o StrictHostKeyChecking=no" git clone -b theori-eval/fp-delta-01 git@github.com:theori-io/afc-freerdp.git $SRC/FreeRDP
WORKDIR $SRC/FreeRDP
