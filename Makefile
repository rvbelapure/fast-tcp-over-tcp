CXX = gcc

LIBDIR = tcp-base

LIBTCP = libtcp.o

all: client.o server.o
	$(CXX) -o client client.o
	$(CXX) -o server server.o

client.o:
	$(CXX) -c client.c $(LIBDIR)/$(LIBTCP)

server.o:
	$(CXX) -c server.c $(LIBDIR)/$(LIBTCP)

clean:
	rm client server *.o


