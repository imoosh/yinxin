#!/bin/bash

set -e

declare -xr TOPDIR=$(cd $(dirname $0)/..; pwd)

#docker load -i "$TOPDIR"/build/uos-server-1070a.tar.gz

bash "$TOPDIR"/build/build_nanomq.sh
bash "$TOPDIR"/build/build_mbedtls.sh
bash "$TOPDIR"/build/build_openvpn.sh

rm -f "$TOPDIR"/artifact/*
cp "$TOPDIR"/_output/*.tar.gz "$TOPDIR"/artifact/
