#!/bin/bash
# iot device subscriber
# kill iotmgr process

PID=$(cat /var/run/iotmgr.pid 2>/dev/null)
if [ -n "$PID" ]; then
    echo "killing iomgr: PID=$PID"
    kill -9 "$PID"
    echo "removing /var/run/iotmgr.pid"
    rm -f /var/run/iotmgr.pid
fi
