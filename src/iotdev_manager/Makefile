MAKE_DIR:= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

all: clean build install pack

build: chdir
	go mod tidy
	go build -o bin/mqttpub ./cmd/mqttpub
	go build -o bin/mqttsub ./cmd/mqttsub
	go build -o bin/iotmgr  ./cmd/iotmgr
	go build -o bin/iotdev  ./cmd/iotdev

clean: chdir
	rm -rf bin/mqttpub bin/mqttsub bin/iotmgr bin/iotdev
	rm -rf release iotmgr*.tar.gz

install: chdir
	mkdir -p release/bin
	mkdir -p release/etc
	mkdir -p release/logs
	cp bin/* release/bin/
	cp etc/iotmgr.yaml release/etc/
	cp etc/iotdev.yaml release/etc/

pack: chdir
	tar -cvzf iotmgr-v1.0.tar.gz release --transform='s/^release/iotmgr/g'

chdir:
	cd $(MAKE_DIR)

.PHONY: all clean build install chdir pack
