#!/bin/bash
# install nanomq/mbedtls/openvpn

set -e

declare -xr CWD=$(cd $(dirname $0); pwd)

# install dir
declare -xr DIR=/usr/local

tar -xf "$CWD"/iotmgr-v1.0.tar.gz -C "$DIR" --strip-components=1
tar -xf "$CWD"/nanomq-0.23.10.tar.gz -C "$DIR" --strip-components=1
tar -xf "$CWD"/openvpn-v2.6.14.tar.gz -C "$DIR" --strip-components=1
tar -xf "$CWD"/mbedtls-v2.28.10.tar.gz -C "$DIR" --strip-components=1

echo "/usr/local/lib64" > /etc/ld.so.conf.d/nanomq.conf
ldconfig

ln -sf /usr/local/etc/nanomq_old.conf /etc/nanomq_old.conf
