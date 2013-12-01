CC = gcc
CCFLAGS= -g -pthread -lm
CCFLAGS= -pthread -lm
LIBDIR= ../transactional-tcp
TCPLIB= ../transactional-tcp/gt-tcplib.o

all: echo-client echo-server web-client web-server

web-client: web-client.o $(TCPLIB)
	$(CC) web-client.o $(TCPLIB) -o web-client $(CCFLAGS)

web-client.o: web-client.c
	$(CC) $(CCFLAGS) -c web-client.c

web-server: web-server.o $(TCPLIB)
	$(CC) web-server.o $(TCPLIB) -o web-server $(CCFLAGS)

web-server.o: web-server.c
	$(CC) $(CCFLAGS) -c web-server.c

echo-client: echo-client.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o echo-client echo-client.o $(TCPLIB) -pthread

echo-server: echo-server.o $(TCPLIB)
	$(CC) $(CCFLAGS) -o echo-server echo-server.o $(TCPLIB) -pthread

echo-client.o: echo-client.c
	$(CC) $(CCFLAGS) -c echo-client.c

echo-server.o: echo-server.c
	$(CC) $(CCFLAGS) -c echo-server.c 

$(TCPLIB): $(LIBDIR)/*.c $(LIBDIR)/*.h
	make -C $(LIBDIR)

clean:
	rm -f echo-client echo-server web-client web-server *.o
