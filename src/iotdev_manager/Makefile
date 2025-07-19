BINARY = iotdev_manager

all: clean build install

build:
	go mod tidy
	go build -o $(BINARY) ./cmd/main.go

clean:
	rm -rf release $(BINARY)

install:
	mkdir -p release/bin
	mkdir -p release/etc
	mkdir -p release/logs
	cp $(BINARY) release/bin/
	cp etc/config.yaml release/etc/

.PHONY: all clean build install
