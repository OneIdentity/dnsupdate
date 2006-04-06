CFLAGS=	 $(shell vas-config --cflags) -I.
#CFLAGS+= -Wall -O0 -ggdb 
LDFLAGS= $(shell vas-config --libs)
OBJS=	dnsupdate.o dns.o dnstcp.o dnsdebug.o dnstkey.o dnstsig.o
PROG=	dnsupdate
$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS)
clean:
	rm -f $(PROG) $(OBJS)
