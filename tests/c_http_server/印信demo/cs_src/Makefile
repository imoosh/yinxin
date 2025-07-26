#
CC = /usr/bin/gcc


#CFLAGS = -Wall -O3 -Werror -Wstrict-prototypes -D_GNU_SOURCE #-DDEBUG
CFLAGS = -Wall -O3 -Werror -D_GNU_SOURCE #-DDEBUG
CFLAGS += -I../include -I../../include  -I ./sslvpn/iotvpn_plugin -I .
LDFLAGS += -L../../lib 

OBJS = http_parser.o buff.o ssl.o cJSON.o utils.o libiotvpn_plugin_wrapper.o
all: ccmdemon

ccmdemon: $(OBJS) http.o server.o http_json.o libiotvpn_plugin_wrapper.o
	$(CC) -o $@ $^   $(LDFLAGS) -lev -liotvpn_plugin

.c.o:
	$(CC) -c -o $*.o $(CFLAGS)  $*.c

libiotvpn_plugin_wrapper.o:
	$(CC) -c -o libiotvpn_plugin_wrapper.o $(CFLAGS)  ./sslvpn/iotvpn_plugin/libiotvpn_plugin_wrapper.c

clean:
	rm -f *.o sm3sum cpuid randtest randfile  lib/*.o $(RAND_PATH)/*.o

