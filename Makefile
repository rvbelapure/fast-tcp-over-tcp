APPSDIR = apps
TCPBASEDIR = tcp-base

all:
	make -C $(TCPBASEDIR)
	make -C $(APPSDIR)

clean:
	make -C $(TCPBASEDIR) clean
	make -C $(APPSDIR) clean
