#!/bin/bash
# iot device subscriber

declare -xr CWD=$(cd $(dirname $0); pwd)

if [ -n "$(pidof iotmgr)" ]; then
    echo "One iotmgr instance is still running! PID: $(pidof iotmgr)"
    exit 1
fi

"$CWD"/iotmgr -d -c "$CWD"/../etc/iotmgr.yaml
