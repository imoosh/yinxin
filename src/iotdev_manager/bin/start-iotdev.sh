#!/bin/bash
# iot device publisher mocker

declare -xr CWD=$(cd $(dirname $0); pwd)

if [ -n "$(pidof iotdev)" ]; then
    echo "One iotdev instance is still running! PID: $(pidof iotdev)"
    exit 1
fi

"$CWD"/iotdev -c "$CWD"/../etc/iotdev.yaml
