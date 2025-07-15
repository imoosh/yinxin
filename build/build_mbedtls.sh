#!/bin/bash
# build mbedtls

declare -xr TOPDIR=$(cd $(dirname $0)/..; pwd)

declare -xr BUILD_IMAGE="docker.io/ixuzhi/uos-server-1070a:latest"
declare -xr OUTPUT_DIR="$TOPDIR"/_output
declare -xr SRCDIR="$TOPDIR"/_output/mbedtls
declare -xr MBEDTLS_VER="v2.28.10"

mkdir -p "$OUTPUT_DIR"
rm -rf "$SRCDIR"
tar -xf "$TOPDIR"/refs/mbedtls-${MBEDTLS_VER}.tar.gz -C "$OUTPUT_DIR"

docker run -it --net=host -w /opt -v "$SRCDIR":/opt "$BUILD_IMAGE" bash -c "
    yum groupinstall -y 'Development Tools'
    yum install -y cmake python3
    mkdir build && cd build
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On -DCMAKE_INSTALL_PREFIX=\$(pwd)/../_output ..
    make && make install
    cd ..
    tar -cvzf mbedtls-${MBEDTLS_VER}.tar.gz --transform='s/^_output/mbedtls/g' _output
"

cp "$SRCDIR"/mbedtls-${MBEDTLS_VER}.tar.gz "$OUTPUT_DIR"
