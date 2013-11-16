CXX = gcc

APPSDIR = apps
TCPBASEDIR = tcp-base

all:
	cd $(TCPBASEDIR) && $(MAKE)
	cd $(APPSDIR) && $(MAKE)

clean:
	cd $(APPSDIR) && $(MAKE) -C . clean
	cd $(TCPBASEDIR) && $(MAKE) -C . clean
	
