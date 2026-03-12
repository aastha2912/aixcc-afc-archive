FROM ubuntu:24.04

ARG PYTHON_VERSION=3.13.7

# Install all apt dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt install -y build-essential curl docker.io docker-buildx git git-lfs unzip \
    pkg-config protobuf-compiler flex bison libnl-route-3-dev software-properties-common openjdk-17-jdk \
    universal-ctags global patchutils rustup musl-tools clang sudo ripgrep wget \
    libssl-dev \
    zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev tk-dev \
    uuid-dev libgdbm-dev libnss3-dev libdb5.3-dev libexpat1-dev \
    python3 python3-venv python3-dev \
    && rustup default stable \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && apt-get autoclean -y \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp \
    && wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz \
    && tar -xzf Python-${PYTHON_VERSION}.tgz \
    && cd Python-${PYTHON_VERSION} \
    && ./configure --prefix=/opt/python-${PYTHON_VERSION} --enable-optimizations --with-ensurepip=install \
    && make -j"$(nproc)" \
    && make install \
    && ln -sf /opt/python-${PYTHON_VERSION}/bin/python3.13 /usr/local/bin/python3.13 \
    && ln -sf /opt/python-${PYTHON_VERSION}/bin/python3.13 /usr/local/bin/python3 \
    && ln -sf /opt/python-${PYTHON_VERSION}/bin/pip3.13 /usr/local/bin/pip3 \
    && rm -rf /tmp/Python-${PYTHON_VERSION} /tmp/Python-${PYTHON_VERSION}.tgz

# install azcopy
RUN . /etc/os-release && wget https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm -f packages-microsoft-prod.deb && \
    apt-get -y update && \
    apt-get -y install azcopy && \
    curl -sL https://aka.ms/InstallAzureCLIDeb | bash

RUN mkdir -p /crs /crs/external/infer /crs/external/llvm-cov
WORKDIR /crs

# (aastham) fetch infer - SKIPPED: Azure blob storage account is disabled
# RUN curl -L https://de6543ab956de244.blob.core.windows.net/files/infer_2232d6b.tar.xz | tar -Jxf - -C external/infer/
# RUN wget https://de6543ab956de244.blob.core.windows.net/files/llvm-cov -O external/llvm-cov/llvm-cov && chmod +x external/llvm-cov/llvm-cov

# (aastham) fetch corpus sample - SKIPPED: Azure blob storage account is disabled
# RUN azcopy copy https://de6543ab956de244.blob.core.windows.net/files/sample.tar.xz /crs/external/corpus/sample.tar.xz

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
# RUN python3 -m venv .venv \
#  && .venv/bin/python -m pip install --upgrade pip \
#  && .venv/bin/pip install --no-cache-dir .
 
COPY ./crs ./crs
COPY ./.git ./.git

# COPY ./run.sh ./run.sh
# ENTRYPOINT ["/crs/run.sh"]
