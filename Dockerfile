FROM ubuntu:24.04

# Install all apt dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt install -y build-essential curl docker.io docker-buildx git git-lfs unzip \
    pkg-config protobuf-compiler flex bison libnl-route-3-dev software-properties-common openjdk-17-jdk \
    universal-ctags global patchutils rustup musl-tools clang sudo ripgrep wget \
    libssl-dev \
    && rustup default stable \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt update \
    && apt install -y python3.13 python3.13-dev python3.13-venv \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && apt-get autoclean -y \
    && rm -rf /var/lib/apt/lists/*

# install azcopy
RUN . /etc/os-release && wget https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm -f packages-microsoft-prod.deb && \
    apt-get -y update && \
    apt-get -y install azcopy && \
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash

RUN mkdir -p /crs /crs/external/infer /crs/external/llvm-cov
WORKDIR /crs

# fetch infer
RUN curl -L https://de6543ab956de244.blob.core.windows.net/files/infer_2232d6b.tar.xz | tar -Jxf - -C external/infer/
RUN wget https://de6543ab956de244.blob.core.windows.net/files/llvm-cov -O external/llvm-cov/llvm-cov && chmod +x external/llvm-cov/llvm-cov

# fetch corpus sample
RUN azcopy copy https://de6543ab956de244.blob.core.windows.net/files/sample.tar.xz /crs/external/corpus/sample.tar.xz

# install kaitai
RUN curl -LO https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/0.10/kaitai-struct-compiler_0.10_all.deb
RUN apt-get install ./kaitai-struct-compiler_0.10_all.deb

# Build external dependencies and utils
COPY ./utils ./utils
COPY ./external ./external
COPY build.sh ./
RUN ./build.sh

RUN git config --system --add safe.directory '*'

# Install our python dependencies
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.toml
COPY ./pyproject.toml ./pyproject.toml
RUN python3.13 -m venv .venv && .venv/bin/pip install .
COPY ./crs ./crs
COPY ./.git ./.git

# COPY ./run.sh ./run.sh
# ENTRYPOINT ["/crs/run.sh"]
