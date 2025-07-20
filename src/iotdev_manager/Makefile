MAKE_DIR:= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

all: clean build install

build: chdir
	go mod tidy
	go build -o bin/mqttpub ./cmd/mqttpub
	go build -o bin/mqttsub ./cmd/mqttsub
	go build -o bin/iotmgr  ./cmd/iotmgr
	go build -o bin/iotdev  ./cmd/iotdev

clean: chdir
	rm -rf bin/* release

install: chdir
	mkdir -p release/bin
	mkdir -p release/etc
	mkdir -p release/logs
	cp bin/* release/bin/
	cp etc/config.yaml release/etc/
	cp start-iotdev.sh start-iotmgr.sh release/

chdir:
	cd $(MAKE_DIR)

.PHONY: all clean build install chdir
