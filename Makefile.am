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
dnsupdate_SOURCES+=	err.c err.h
dnsupdate_LDADD=	$(LIBOBJS)
dnsupdate_CFLAGS=	$(VAS_CFLAGS)
dnsupdate_LDFLAGS=	$(VAS_LIBS)
dnsupdate_CPPFLAGS=	-DPATH_SYSCONFDIR=\"$(sysconfdir)\"

EXTRA_DIST=	$(man_MANS) \
		dnsupdate-install-hooks.in dnsupdate.pp pp
CLEANFILES= 	dnsupdate-install-hooks
DISTCLEANFILES = $(PP)

SUBST=	sed -e 's,[@]datadir[@],$(datadir),g' \
	    -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
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
	       MachineXlatorsdir=$(MachineXlatorsdir) \
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

noinst_PROGRAMS=	server-t
server_t_SOURCES=	server-t.c
server_t_SOURCES+=	common.h 
server_t_SOURCES+=	dns.c dns.h
server_t_SOURCES+=	err.c err.h
server_t_SOURCES+=	dnstcp.c dnstcp.h
server_t_SOURCES+=	dnsdebug.c dnsdebug.h
server_t_LDADD=		$(LIBOBJS)

TESTS=			$(check_PROGRAMS)

POLYPKGFILE=/data/rc/pub/rc/polypkg/pp
POLYPKGURI=http://rc.quest.com/pub/rc/polypkg/pp

$(PP):
	if [ -r "$(POLYPKGFILE)" ]; then \
	    ln -s $(POLYPKGFILE) $@; \
	elif which wget >/dev/null 2>&1; then \
	    wget -O $@ "$(POLYPKGURI)"; \
	elif which curl >/dev/null 2>&1; then \
	    curl -o $@ "$(POLYPKGURI)"; \
	else \
	    echo "Cannot figure out how to get polypkg"; \
	    exit 1; \
	fi

MachineXlatorsdir = $(libexecdir)/vgp/xlators/Machine
MachineXlators_SCRIPTS = quest-dnsupdate-xlator
quest-dnsupdate-xlator: xlator.sh.in
	$(SUBST) <$(srcdir)/xlator.sh.in > $@
	chmod +x $@
xlator-t: xlator-t.sh
	cat $(srcdir)/xlator-t.sh > $@
	chmod +x $@

check_PROGRAMS += xlator-t
xlator_t_SOURCES = xlator-t.sh
EXTRA_DIST += xlator.sh.in 
CLEANFILES += quest-dnsupdate-xlator 

dnsupdate-t: dnsupdate-t.sh
	cat $(srcdir)/dnsupdate-t.sh > $@
	chmod +x $@
check_PROGRAMS+=	dnsupdate-t
dnsupdate_t_SOURCES = dnsupdate-t.sh
