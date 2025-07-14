FROM gcr.io/oss-fuzz-base/base-builder:latest

RUN sed -i '/deb-src/s/^# //' /etc/apt/sources.list
RUN apt-get update && apt-get -y install ninja-build libz-dev && apt-get -y build-dep llvm
RUN mkdir -p /root/build && cd /root/build
WORKDIR /root/build
RUN git clone -b llvmorg-20.1.6 https://github.com/llvm/llvm-project.git
RUN mkdir build && cd build
WORKDIR /root/build/llvm-project/build
RUN LD=lld CC=clang CXX=clang++ cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=${PWD}/release \
    -DCMAKE_OSX_ARCHITECTURES='x86_64;arm64' \
    -DCLANG_ENABLE_BOOTSTRAP=ON \
    -DLIBCLANG_BUILD_STATIC=ON \
    -DLLVM_ENABLE_BINDINGS=OFF \
    -DLLVM_ENABLE_LIBXML2=OFF \
    -DLLVM_ENABLE_LTO=OFF \
    -DLLVM_ENABLE_OCAMLDOC=OFF \
    -DLLVM_ENABLE_PIC=OFF \
    -DLLVM_ENABLE_PROJECTS='clang;lld' \
    -DLLVM_ENABLE_TERMINFO=OFF \
    -DLLVM_ENABLE_WARNINGS=OFF \
    -DLLVM_ENABLE_Z3_SOLVER=OFF \
    -DLLVM_ENABLE_ZLIB=FORCE_ON \
    -DLLVM_ENABLE_ZSTD=OFF \
    -DLLVM_HAVE_LIBXAR=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_TOOL_REMARKS_SHLIB_BUILD=OFF \
    -G Ninja \
    ../llvm
RUN ninja
