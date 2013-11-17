CC = gcc
CCFLAGS= -g
LIBDIR= ../tcp-base
TCPLIB= ../tcp-base/gt-tcplib.o

all: client server

client: client.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o client client.o $(TCPLIB)

server: server.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o server server.o $(TCPLIB)

client.o: client.c
	$(CC) $(CCFLAGS) -c client.c

server.o:
	$(CC) $(CCFLAGS) -c server.c 

$(TCPLIB): $(LIBDIR)/*.c $(LIBDIR)/*.h
	make -C $(LIBDIR)

clean:
	rm -f client server *.o
