$!/bin/bash
cp openvpn.service /etc/systemd/system/openvpn.service
systemctl daemon-reload

LD_LIBRARY_PATH=/usr/local/openvpn/lib/openvpn:/usr/local/openvpn/lib/tls \
  /usr/local/openvpn/sbin/openvpn --config  /var/lib/iot/sslvpn/openvpn/server.conf

