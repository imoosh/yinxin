all: clean build pack

build:
	$(MAKE) -C src/iotvpn_config_manager_plugin
	$(MAKE) -C src/iotdev_manager

clean:
	rm -rf release
	mkdir -p release

pack:
	cp src/iotdev_manager/iotmgr-v1.0.tar.gz release/
	cp src/iotvpn_config_manager_plugin/libiotvpn_plugin-v1.0.tar.gz release/

.PHONY: all clean build
