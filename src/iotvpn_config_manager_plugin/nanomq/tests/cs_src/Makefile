#
CC = /usr/bin/gcc


#CFLAGS = -Wall -O3 -Werror -Wstrict-prototypes -D_GNU_SOURCE #-DDEBUG
CFLAGS = -Wall -O3 -Werror -D_GNU_SOURCE #-DDEBUG
#CFLAGS += -Ihygon -Ilib
CFLAGS += -I../../../build_tmp
LDFLAGS = -lev -L../../../build_tmp -liotvpn_plugin

OBJS = http_parser.o buff.o ssl.o cJSON.o utils.o
all: ccmdemon

ccmdemon: $(OBJS) http.o server.o http_json.o
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $*.o $(CFLAGS)  $*.c

clean:
	rm -f *.o sm3sum cpuid randtest randfile ccmdemon lib/*.o $(RAND_PATH)/*.o

