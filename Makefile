TCPAPPS= apps-tcp-base
TFOAPPS= apps-tcp-fast-open
TTCPAPPS = apps-transactional-tcp

TCPBASEDIR= tcp-base
TFODIR= tcp-fast-open
TTCPDIR= transactional-tcp

# only make in apps directory is sufficient as it will recursively build everything
all: tfo-apps ttcp-apps base-apps

tfo-apps:
	make -C $(TFOAPPS) LIBDIR=../$(TFODIR) TCPLIB=../$(TFODIR)/gt-tcplib.o

ttcp-apps:
	make -C $(TTCPAPPS) LIBDIR=../$(TTCPDIR) TCPLIB=../$(TTCPDIR)/gt-tcplib.o

base-apps:
	make -C $(TCPAPPS) LIBDIR=../$(TCPBASEDIR) TCPLIB=../$(TCPBASEDIR)/gt-tcplib.o

clean:
	make -C $(TCPBASEDIR) clean
	make -C $(TFODIR) clean
	make -C $(TTCPDIR) clean
	make -C $(TCPAPPS) clean
	make -C $(TFOAPPS) clean
	make -C $(TTCPAPPS) clean
