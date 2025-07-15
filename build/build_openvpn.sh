#!/bin/bash
# build openvpn

declare -xr TOPDIR=$(cd $(dirname $0)/..; pwd)

declare -xr BUILD_IMAGE="docker.io/ixuzhi/uos-server-1070a:latest"
declare -xr OUTPUT_DIR="$TOPDIR"/_output
declare -xr SRCDIR="$TOPDIR"/_output/openvpn
declare -xr OPENVPN_VER="v2.6.14"
declare -xr MBEDTLS_VER="v2.28.10"

# mbedtls
#declare -xr SSLPKG="libmbedtls-dev"
declare -xr SSLLIB="mbedtls"
declare -xr PKCS11PKG=""
declare -xr EXTRACONF=""

# openssl
#declare -xr SSLPKG="libssl-dev"
#declare -xr SSLLIB="openssl"
#declare -xr PKCS11PKG="libpkcs11-helper1-dev softhsm2 gnutls-bin"
#declare -xr EXTRACONF="--enable-pkcs11"


mkdir -p "$OUTPUT_DIR"
rm -rf "$SRCDIR"
tar -xf "$TOPDIR"/refs/openvpn-${OPENVPN_VER}.tar.gz -C "$OUTPUT_DIR"
cp "$OUTPUT_DIR"/mbedtls-${MBEDTLS_VER}.tar.gz "$SRCDIR"

docker run -it --net=host -w /opt -v "$SRCDIR":/opt "$BUILD_IMAGE" bash -c "
    yum install -y lzo-devel pam-devel lz4-devel libcap-ng-devel libnl3-devel glibc-devel glibc-devel \
        libcmocka-devel python3-docutils libtool automake autoconf make pkg-config ${SSLPKG} ${PKCS11PKG}
    echo apt install -y liblzo2-dev libpam0g-dev liblz4-dev libcap-ng-dev libnl-genl-3-dev linux-libc-dev \
        man2html libcmocka-dev python3-docutils libtool automake autoconf make pkg-config ${SSLPKG} ${PKCS11PKG}
    tar -xf mbedtls-${MBEDTLS_VER}.tar.gz -C /usr/local --strip-components=1
    autoreconf -fvi
    ./configure --with-crypto-library=${SSLLIB} ${EXTRACONF} --enable-werror --prefix=\$(pwd)/_output
    make -j3 && make install
    #echo 'RUN_SUDO=\"sudo -E\"' >tests/t_server_null.rc
    #make -j3 check VERBOSE=1
    tar -cvzf openvpn-${OPENVPN_VER}.tar.gz --transform='s/^_output/openvpn/g' _output
"

cp "$SRCDIR"/openvpn-${OPENVPN_VER}.tar.gz "$OUTPUT_DIR"
