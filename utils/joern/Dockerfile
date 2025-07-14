FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update \
    && apt install -y curl git openjdk-17-jdk sudo unzip wget
    
RUN echo "deb https://repo.scala-sbt.org/scalasbt/debian all main" | sudo tee /etc/apt/sources.list.d/sbt.list \
    && echo "deb https://repo.scala-sbt.org/scalasbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt_old.list \
    && curl -sL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2EE0EA64E40A89B84B2DF73499E82A75642AC823" | sudo tee /etc/apt/trusted.gpg.d/sbt.asc \
    && apt-get update \
    && sudo apt-get install sbt \
    && apt-get clean

RUN mkdir /tmp/joern-custom \
    && git clone https://github.com/joernio/joern.git /tmp/joern-custom \
    && cd /tmp/joern-custom \
    && git checkout 8056945b2a4fe68d59f9b369a988f2c2ab2356f7 \
    && sed -i '84s/^/\/\//' /tmp/joern-custom/joern-cli/frontends/c2cpg/src/main/scala/io/joern/c2cpg/C2Cpg.scala

RUN chmod +x /tmp/joern-custom/joern-install.sh \
    && sed -i '159s|.*|        mv /tmp/joern-custom/target/joern-cli.zip /tmp/joern-custom/|' /tmp/joern-custom/joern-install.sh \
    && cd /tmp/joern-custom \
    && /tmp/joern-custom/joern-install.sh --no-download \
    && rm -rf /tmp/*
