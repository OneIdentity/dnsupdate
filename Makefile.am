# (c) 2006, Quest Software, Inc, All rights reserved.

AUTOMAKE_OPTIONS=       foreign

VAS_CFLAGS=		`$(VASCONFIG) --cflags vas`
VAS_LIBS=		`$(VASCONFIG) --libs vas`

sbin_PROGRAMS = 	dnsupdate
man_MANS = 		dnsupdate.8

dnsupdate_SOURCES=	dnsupdate.c dns.c dnstcp.c \
			dnsdebug.c dnstkey.c dnstsig.c \
			common.h dns.h dnsdebug.h dnstcp.h \
			dnstkey.h dnstsig.h
dnsupdate_LDADD=	$(LIBOBJS)
dnsupdate_CFLAGS=	$(VAS_CFLAGS)
dnsupdate_LDFLAGS=	$(VAS_LIBS)

dnsupdate.spec: dnsupdate.spec.in
	sed -e 's,[@]VERSION[@],$(VERSION),g' < $(srcdir)/dnsupdate.spec.in > $@

EXTRA_DIST=	dnsupdate.spec dnsupdate.spec.in $(man_MANS) err.h


