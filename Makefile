APPSDIR = apps
TCPBASEDIR = tcp-base

# only make in apps directory is sufficient as it will recursively build everything
applications:
	make -C $(APPSDIR)

clean:
	make -C $(TCPBASEDIR) clean
	make -C $(APPSDIR) clean
