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


# install openvpn service
echo '[Unit]
Description=OpenVPN service
After=network.target

[Service]
Type=simple
PrivateTmp=true

ExecStart=/usr/local/sbin/openvpn --config  /var/lib/iot/sslvpn/openvpn/server.conf
PIDFile=/run/openvpn.pid
WorkingDirectory=/var/lib/iot/sslvpn/openvpn/
User=root
Group=root
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target' > /usr/lib/systemd/system/openvpn.service

systemctl daemon-reload 