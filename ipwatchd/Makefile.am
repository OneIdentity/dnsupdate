
progdatadir=		$(datadir)/ipwatchd

sbin_PROGRAMS=		ipwatchd
man_MANS =		ipwatchd.8
progdata_DATA=		com.quest.rc.ipwatchd.plist

ipwatchd_SOURCES=	ipwatchd.c watch.c watch.h
ipwatchd_LDFLAGS=	-framework CoreFoundation
ipwatchd_LDFLAGS+=	-framework SystemConfiguration

SUBST=	$(SED) -e 's,[@]sbindir[@],$(sbindir),g'
com.quest.rc.ipwatchd.plist: $(srcdir)/com.quest.rc.ipwatchd.plist.in
	$(SUBST) < $(srcdir)/com.quest.rc.ipwatchd.plist.in > $@

EXTRA_DIST = com.quest.rc.ipwatchd.plist.in $(man_MANS)
CLEANFILES = com.quest.rc.ipwatchd.plist
