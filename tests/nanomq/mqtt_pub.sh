#!/bin/bash

declare TOPIC="test"
declare QOS=2

nanomq_cli pub -t "$TOPIC" -q "$QOS" -p 8883 -s --cafile /etc/certs/ca.pem --cert /etc/certs/client.pem --key /etc/certs/client-key.pem -l
