#!/bin/bash

function nanomq_start() {
    nanomq start -d --conf /etc/nanomq.conf --log_file /var/log/nanomq.log --log_syslog true --log_level trace
}

function nanomq_stop() {
    nanomq stop
}

function nanomq_restart() {
    nanomq_stop
    nanomq_start
}

function nanomq_status() {
    local NANOMQ_PID=$(pidof nanomq)
    local PIDFILE_PID=$(cat /tmp/nanomq/nanomq.pid 2>&- | tr -d '\0')
    if [ -n "$NANOMQ_PID" ] && [ "$NANOMQ_PID" = "$PIDFILE_PID" ]; then
        echo "NanoMQ is OK"
        exit 0
    else 
        echo "NanoMQ is Abnormal"
        exit 1
    fi
}

function nanomq_usage() {
    echo "$(basename $0) { start | stop | restart | status }"
}

case $1 in
    start)   nanomq_start ;;
    stop)    nanomq_stop ;;
    restart) nanomq_restart ;;
    status)  nanomq_status ;;
    *)       nanomq_usage ;;
esac
