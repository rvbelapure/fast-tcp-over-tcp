CC = gcc
LD = ld
CCFLAGS = -g

# Creating single relocatable object gt-tcplib.o from all sources
# Link your applications with this object instead of several sources
gt-tcplib.o : libtcp.o tcputils.o pkt_queue.o
	$(LD) -r libtcp.o tcputils.o pkt_queue.o -o gt-tcplib.o

libtcp.o: libtcp.c tcp.h tcputils.h pkt_queue.h
	$(CC) $(CCFLAGS) -c libtcp.c 

tcputils.o: tcputils.c tcputils.h tcp.h
	$(CC) $(CCFLAGS) -c tcputils.c 

pkt_queue.o: pkt_queue.c pkt_queue.h
	$(CC) $(CCFLAGS) -c pkt_queue.c

clean:
	rm -f *.o
