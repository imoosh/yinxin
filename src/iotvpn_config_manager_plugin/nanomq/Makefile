all:
	go build -o libnanomq.so -buildmode=c-shared nanomq_plugin.go nanomq_conf.go nanomq_log.go
	chmod +x libnanomq.so

clean:
	rm -f libnanomq.so

.PHONY: all clean
