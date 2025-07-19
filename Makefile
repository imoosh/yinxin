all:
	$(MAKE) -C src/iotvpn_config_manager_plugin

clean:
	rm -rf release
	mkdir -p release

.PHONY: all clean
