CFLAGS=	-Wall -O0 -ggdb $(shell vas-config --cflags)
LDFLAGS= $(shell vas-config --libs)
OBJS=	dnstest.o dns.o dnstcp.o dnsdebug.o dnstkey.o dnstsig.o
PROG=	dnstest
$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
clean:
	rm -f $(PROG) $(OBJS)
