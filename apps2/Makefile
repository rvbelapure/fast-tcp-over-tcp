CC = gcc
CCFLAGS= -g
LIBDIR= ../tcp-base
TCPLIB= ../tcp-base/gt-tcplib.o

all: client server

client: client.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o client client.o $(TCPLIB) -pthread

server: concurrentserver.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o server concurrentserver.o $(TCPLIB) -pthread

client.o: client.c
	$(CC) $(CCFLAGS) -c client.c

concurrentserver.o:
	$(CC) $(CCFLAGS) -c concurrentserver.c 

$(TCPLIB): $(LIBDIR)/*.c $(LIBDIR)/*.h
	make -C $(LIBDIR)

clean:
	rm -f client server *.o
