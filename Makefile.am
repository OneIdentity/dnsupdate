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

EXTRA_DIST=	$(man_MANS) err.h \
		dnsupdate-install-hooks.in dnsupdate.pp pp
CLEAN_FILES= 	dnsupdate-install-hooks

SUBST=	sed \
	    -e 's,[@]datadir[@],$(datadir),g' \
	    -e 's,[@]sbindir[@],$(sbindir),g' \

dnsupdate-install-hooks: $(srcdir)/dnsupdate-install-hooks.in
	$(SUBST) <$(srcdir)/dnsupdate-install-hooks.in > $@
	chmod +x $@

PP=$(srcdir)/pp
TMP_DESTDIR=`pwd`/destdir
package: dnsupdate.pp $(PP)
	DESTDIR=$(TMP_DESTDIR); \
	rm -rf $$DESTDIR; mkdir -p $$DESTDIR; \
	$(MAKE) install DESTDIR=$$DESTDIR; \
	$(PP) \
	       --destdir=$$DESTDIR \
	       --install-script=inst.sh \
	    $(srcdir)/dnsupdate.pp \
	       version=$(VERSION) \
	       sbindir=$(sbindir) \
	       libexecdir=$(libexecdir) \
	       datadir=$(datadir) \
	       man8dir=$(man8dir) \
	       WITH_IPWATCHD=$(WITH_IPWATCHD)

SUBDIRS=
if WITH_IPWATCHD
SUBDIRS+=	ipwatchd
endif
