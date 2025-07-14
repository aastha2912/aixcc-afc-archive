FROM ghcr.io/aixcc-finals/base-builder:v1.3.0
RUN apt-get update && apt-get install -y build-essential

WORKDIR $SRC

# clone private repo via a deploy key
COPY deploy_key $SRC/deploy_key
RUN chmod 600 $SRC/deploy_key
RUN GIT_SSH_COMMAND="ssh -i $SRC/deploy_key -o StrictHostKeyChecking=no" git clone -b theori-eval/integration-test-delta-01 git@github.com:theori-io/afc-integration-test.git $SRC/integration-test

COPY build.sh $SRC/
COPY fuzz_* $SRC/
WORKDIR $SRC/integration-test
