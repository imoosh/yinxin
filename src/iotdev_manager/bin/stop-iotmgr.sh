#!/bin/bash
# iot device subscriber
# kill iotmgr process

PID=$(cat /var/run/iotmgr.pid 2>/dev/null)
if [ -n "$PID" ]; then
    kill -9 "$PID"
    rm -f /var/run/iotmgr.pid
fi
