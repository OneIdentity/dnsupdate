# (c) 2006, Quest Software, Inc, All rights reserved.

AUTOMAKE_OPTIONS=       foreign

VAS_CFLAGS=		`$(VASCONFIG) --cflags vas`
VAS_LIBS=		`$(VASCONFIG) --libs vas`

sbin_PROGRAMS = 	dnsupdate
libexec_SCRIPTS =	dnsupdate-install-hooks
man_MANS = 		dnsupdate.8 dnsupdate-install-hooks.8

dnsupdate_SOURCES=	dnsupdate.c 
dnsupdate_SOURCES+=	common.h 
dnsupdate_SOURCES+=	dns.c dns.h 
dnsupdate_SOURCES+=	dnsdebug.c dnsdebug.h 
dnsupdate_SOURCES+=	dnstcp.c dnstcp.h 
dnsupdate_SOURCES+=	dnstkey.c dnstkey.h 
dnsupdate_SOURCES+=	dnstsig.c dnstsig.h
dnsupdate_SOURCES+=	conf.c conf.h
dnsupdate_SOURCES+=	stream.c stream.h
dnsupdate_SOURCES+=	resconf.c resconf.h
dnsupdate_SOURCES+=	list.c list.h
dnsupdate_LDADD=	$(LIBOBJS)
dnsupdate_CFLAGS=	$(VAS_CFLAGS)
dnsupdate_LDFLAGS=	$(VAS_LIBS)
dnsupdate_CPPFLAGS=	-DPATH_SYSCONFDIR=\"$(sysconfdir)\"

EXTRA_DIST=	$(man_MANS) err.h \
		dnsupdate-install-hooks.in dnsupdate.pp pp
CLEAN_FILES= 	dnsupdate-install-hooks

SUBST=	sed -e 's,[@]datadir[@],$(datadir),g' \
	    -e 's,[@]sbindir[@],$(sbindir),g'

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

check_PROGRAMS=		conf-t
conf_t_SOURCES=		conf-t.c conf.c conf.h stream.c stream.h
conf_t_CFLAGS =		-ggdb

check_PROGRAMS+=	list-t
list_t_SOURCES=		list-t.c list.c list.h
list_t_CFLAGS =		-ggdb

TESTS=			$(check_PROGRAMS)
