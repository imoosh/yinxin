BINARY = libiotvpn_config_manager_plugin
PROJECT_NAME = iotvpn_config_manager_plugin
VERSION = v1.0.0
BUILD = `date +%FT%T%z`
GITHASH = `git rev-parse --short HEAD`

# Directories
RELEASE_DIR = ../../release

# Setup LDFLAGS for version injection
LDFLAGS = -ldflags "-X ${PROJECT_NAME}/version.Version=${VERSION} -X ${PROJECT_NAME}/version.Build=${BUILD} -X ${PROJECT_NAME}/version.GitHash=${GITHASH} -s -w"

# Build flags
CGO_ENABLED = 1
GOOS = linux
GOARCH = amd64

all: clean build package

build:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -buildmode=c-shared $(LDFLAGS) -o build_tmp/$(BINARY).so main.go lib.go nanomq/nanomq_plugin.go


clean:
	rm -f build_tmp/$(BINARY).so


# Package release
package: build
	@echo "Creating release package..."
	@mkdir -p $(RELEASE_DIR)/lib $(RELEASE_DIR)/include
	@cp build_tmp/$(BINARY).so $(RELEASE_DIR)/lib/
	@cp sslvpn/include/sslvpn_api.h $(RELEASE_DIR)/include/



.PHONY: all clean
