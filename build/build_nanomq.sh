#!/bin/bash
# build nanomq

declare -xr TOPDIR=$(cd $(dirname $0)/..; pwd)

declare -xr BUILD_IMAGE="docker.io/ixuzhi/uos-server-1070a:latest"
declare -xr OUTPUT_DIR="$TOPDIR"/_output
declare -xr SRCDIR="$TOPDIR"/_output/nanomq
declare -xr NANOMQ_VER="0.23.10"

mkdir -p "$OUTPUT_DIR"
rm -rf "$SRCDIR"
tar -xf "$TOPDIR"/refs/nanomq-${NANOMQ_VER}.tar.gz -C "$OUTPUT_DIR"

docker run -it --net=host -w /opt -v "$SRCDIR":/opt "$BUILD_IMAGE" bash -c "
    yum groupinstall -y 'Development Tools'
    yum install -y cmake git python3
    git submodule update --init --recursive
    mkdir build && cd build
    cmake -DNNG_ENABLE_TLS=ON -DENABLE_JWT=ON -DCMAKE_INSTALL_PREFIX=\$(pwd)/../_output ..
    make && make install
    cd ..
    tar -cvzf nanomq-${NANOMQ_VER}.tar.gz --transform='s/^_output/nanomq/g' _output
"

cp "$SRCDIR"/nanomq-${NANOMQ_VER}.tar.gz "$OUTPUT_DIR"
