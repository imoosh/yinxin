#!/bin/bash
# build nanomq

declare -xr TOPDIR=$(cd $(dirname $0)/..; pwd)

#declare -xr BUILD_IMAGE="ubuntu:24.04"
declare -xr BUILD_IMAGE="registry.imoosh.top/ubuntu:24.04-dev"
declare -xr OUTPUT_DIR="$TOPDIR"/_output
declare -xr SRCDIR="$TOPDIR"/_output/nanomq
declare -xr NANOMQ_VER="0.23.10"

mkdir -p "$OUTPUT_DIR"
rm -rf "$SRCDIR"
tar -xf "$TOPDIR"/refs/nanomq-${NANOMQ_VER}.tar.gz -C "$OUTPUT_DIR"

docker run -it --net=host -w /opt -v "$SRCDIR":/opt ubuntu:24.04 bash -c "
    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt install -y build-essential cmake git
    git submodule update --init --recursive
    mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=\$(pwd)/../_output ..
    make && make install
    cd ..
    tar -cvzf nanomq-${NANOMQ_VER}.tar.gz --transform='s/^_output/nanomq/g' _output
"

cp "$SRCDIR"/nanomq-${NANOMQ_VER}.tar.gz "$TOPDIR"/artifact
