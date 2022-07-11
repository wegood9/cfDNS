CC=gcc
CFLAGS=-O3 -Wall

cfDNS: main.o server.o client.o socket.o config.o protocol.o hosts.o cache.o hash.o doh.o
	gcc main.o server.o client.o socket.o cache.o hash.o config.o hosts.o protocol.o doh.o -o cfDNS -lm -lpthread

clean:
	${RM} *.o cfDNS

