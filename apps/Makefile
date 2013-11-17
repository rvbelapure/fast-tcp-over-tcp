CC = gcc

LIBDIR = ../tcp-base

all: client server

client: client.o 
	$(CC) -o client client.o $(LIBDIR)/libtcp.o $(LIBDIR)/tcputils.o $(LIBDIR)/pkt_queue.o

server: server.o 
	$(CC) -o server server.o $(LIBDIR)/libtcp.o $(LIBDIR)/tcputils.o $(LIBDIR)/pkt_queue.o

client.o: client.c
	$(CC) -c client.c

server.o:
	$(CC) -c server.c 

clean:
	rm -f client server *.o


