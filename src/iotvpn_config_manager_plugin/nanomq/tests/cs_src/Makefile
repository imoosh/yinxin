#
CC = /usr/bin/gcc


#CFLAGS = -Wall -O3 -Werror -Wstrict-prototypes -D_GNU_SOURCE #-DDEBUG
CFLAGS = -Wall -O3 -Werror -D_GNU_SOURCE #-DDEBUG
#CFLAGS += -Ihygon -Ilib

OBJS = http_parser.o buff.o ssl.o cJSON.o utils.o
all: ccmdemon

ccmdemon: $(OBJS) http.o server.o http_json.o
	$(CC) -o $@ $^ -lev -L. -lnanomq

.c.o:
	$(CC) -c -o $*.o $(CFLAGS)  $*.c

clean:
	rm -f *.o sm3sum cpuid randtest randfile ccmdemon lib/*.o $(RAND_PATH)/*.o

