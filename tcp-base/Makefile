CC = gcc
LD = ld
CCFLAGS = -g

# Creating single relocatable object gt-tcplib.o from all sources
# Link your applications with this object instead of several sources
gt-tcplib.o : libtcp.o tcputils.o
	$(LD) $(CCFLAGS) -r libtcp.o tcputils.o -o gt-tcplib.o

libtcp.o: libtcp.c tcp.h tcputils.h
	$(CC) $(CCFLAGS) -c libtcp.c 

tcputils.o: tcputils.c tcputils.h tcp.h
	$(CC) $(CCFLAGS) -c tcputils.c 

clean:
	rm -f *.o
