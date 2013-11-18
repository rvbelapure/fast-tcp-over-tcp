APPSDIR= apps
TCPBASEDIR= tcp-base
TFODIR= tcp-fast-open
TTCPDIR= transactional-tcp

# only make in apps directory is sufficient as it will recursively build everything
tfo-apps:
	make -C $(APPSDIR) LIBDIR=../$(TFODIR) TCPLIB=../$(TFODIR)/gt-tcplib.o

ttcp-apps:
	make -C $(APPSDIR) LIBDIR=../$(TTCPDIR) TCPLIB=../$(TTCPDIR)/gt-tcplib.o

base-apps:
	make -C $(APPSDIR) LIBDIR=../$(TCPBASEDIR) TCPLIB=../$(TCPBASEDIR)/gt-tcplib.o

clean:
	make -C $(TCPBASEDIR) clean
	make -C $(TFODIR) clean
	make -C $(TTCPDIR) clean
	make -C $(APPSDIR) clean
