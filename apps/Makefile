CC = gcc
CCFLAGS= -g

LIBDIR = ../tcp-base

all: client server

client: client.o 
	$(CC) $(CCFLAGS) -o client client.o $(LIBDIR)/libtcp.o $(LIBDIR)/tcputils.o $(LIBDIR)/pkt_queue.o

server: server.o 
	$(CC) $(CCFLAGS) -o server server.o $(LIBDIR)/libtcp.o $(LIBDIR)/tcputils.o $(LIBDIR)/pkt_queue.o

client.o: client.c
	$(CC) $(CCFLAGS) -c client.c

server.o:
	$(CC) $(CCFLAGS) -c server.c 

clean:
	rm -f client server *.o
