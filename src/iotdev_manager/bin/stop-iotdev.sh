#!/bin/bash
# iot device subscriber
# kill iotdev process

PID=$(cat /var/run/iotdev.pid 2>/dev/null)
if [ -n "$PID" ]; then
    kill -9 "$PID"
    rm -f /var/run/iotdev.pid
fi
