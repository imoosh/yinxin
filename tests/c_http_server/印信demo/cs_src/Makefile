#
CC = /usr/bin/gcc


#CFLAGS = -Wall -O3 -Werror -Wstrict-prototypes -D_GNU_SOURCE #-DDEBUG
CFLAGS = -Wall -O3 -Werror -D_GNU_SOURCE #-DDEBUG
CFLAGS += -I../include -I../../include 
LDFLAGS += -L../../lib 

OBJS = http_parser.o buff.o ssl.o cJSON.o utils.o
all: ccmdemon

ccmdemon: $(OBJS) http.o server.o http_json.o sslvpn_http_wrapper.o
	$(CC) -o $@ $^   $(LDFLAGS) -lev -liotvpn_plugin

.c.o:
	$(CC) -c -o $*.o $(CFLAGS)  $*.c

clean:
	rm -f *.o sm3sum cpuid randtest randfile  lib/*.o $(RAND_PATH)/*.o

