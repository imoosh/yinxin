#!/bin/bash
# iot device publisher mocker

if [ -n "$(pidof iotdev)" ]; then
    echo "One iotdev instance is still running! PID: $(pidof iotdev)"
    exit 1
fi

./bin/iotdev -c ./etc/config.yaml
