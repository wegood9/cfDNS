CC=gcc
CFLAGS=-g -Wall

cfDNS: main.o socket.o config.o protocol.o
	gcc main.o socket.o config.o protocol.o -o cfDNS -lm

clean:
	${RM} *.o cfDNS *.log

