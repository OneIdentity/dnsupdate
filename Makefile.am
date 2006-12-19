# (c) 2006, Quest Software, Inc, All rights reserved.

AUTOMAKE_OPTIONS=       foreign

VAS_CFLAGS=		`$(VASCONFIG) --cflags vas`
VAS_LIBS=		`$(VASCONFIG) --libs vas`

sbin_PROGRAMS = 	dnsupdate
man_MANS = 		dnsupdate.8
libexec_SCRIPTS =	dnsupdate-install-hooks

dnsupdate_SOURCES=	dnsupdate.c dns.c dnstcp.c \
			dnsdebug.c dnstkey.c dnstsig.c \
			common.h dns.h dnsdebug.h dnstcp.h \
			dnstkey.h dnstsig.h
dnsupdate_LDADD=	$(LIBOBJS)
dnsupdate_CFLAGS=	$(VAS_CFLAGS)
dnsupdate_LDFLAGS=	$(VAS_LIBS)

dnsupdate.spec: dnsupdate.spec.in
	sed -e 's,[@]VERSION[@],$(VERSION),g' < $(srcdir)/dnsupdate.spec.in > $@

EXTRA_DIST=	$(man_MANS) err.h \
		dnsupdate-install-hooks dnsupdate.pp pp

package: dnsupdate.pp pp
	DESTDIR=`pwd`/destdir; \
	rm -rf $$DESTDIR; mkdir -p $$DESTDIR; \
	$(MAKE) install DESTDIR=$$DESTDIR; \
	$(srcdir)/pp \
	    --destdir=$$DESTDIR $(srcdir)/dnsupdate.pp \
	    --install-script=inst.sh \
	    version=$(VERSION) \
	    sbindir=$(sbindir) \
	    libexecdir=$(libexecdir) \
	    man8dir=$(man8dir)
