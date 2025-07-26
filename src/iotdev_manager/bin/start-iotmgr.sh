#!/bin/bash
# iot device subscriber

declare -xr CWD=$(cd $(dirname $0); pwd)
declare -xr BIN_PATH="$CWD"
declare -xr ETC_PATH="$(cd "$BIN_PATH"/../etc; pwd)"

if [ -n "$(pidof iotmgr)" ]; then
    echo "One iotmgr instance is still running! PID: $(pidof iotmgr)"
    exit 1
fi

case $1 in 
    -d)
        "$BIN_PATH"/iotmgr -d -c "$ETC_PATH"/iotmgr.yaml
        ;;
    *)
        "$BIN_PATH"/iotmgr -c "$ETC_PATH"/iotmgr.yaml
esac
