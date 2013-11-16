CXX = gcc

LIBDIR = ../tcp-base

all: client server

client: client.o 
	$(CXX) -o client client.o $(LIBDIR)/libtcp.o

server: server.o 
	$(CXX) -o server server.o $(LIBDIR)/libtcp.o

client.o: client.c
	$(CXX) -c client.c

server.o:
	$(CXX) -c server.c 

clean:
	rm client server *.o


