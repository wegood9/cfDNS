CC=gcc
CFLAGS=-g -Wall -lpthread

cfDNS: main.o server.o client.o socket.o config.o protocol.o hosts.o cache.o hash.o
	gcc main.o server.o client.o socket.o cache.o hash.o config.o hosts.o protocol.o -o cfDNS -lm

clean:
	${RM} *.o cfDNS *.log

