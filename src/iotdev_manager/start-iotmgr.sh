#!/bin/bash
# iot device subscriber

if [ -n "$(pidof iotmgr)" ]; then
    echo "One iotmgr instance is still running! PID: $(pidof iotmgr)"
    exit 1
fi

./bin/iotmgr -c ./etc/config.yaml
