# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([dnsupdate],
	[1.3.0.]esyscmd(svnversion -n . /trunk || echo 0),
	[support@quest.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([dnsupdate.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])
AC_SUBST([mandir], ['${prefix}/man'])

AC_PROG_CC
AC_C_CONST
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([netdb.h unistd.h sys/socket.h errno.h netinet/in.h])

AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_ERROR([vas-config was not found; is the VAS SDK installed?])
fi
AC_SUBST([VASCONFIG])

AC_CHECK_FUNC([getaddrinfo])
AC_CHECK_FUNC([getopt], [], [AC_LIBOBJ([getopt])])
AC_CHECK_FUNCS([err errx warn warnx], [], [AC_LIBOBJ([err])
break])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl])


AC_CHECK_TYPE([socklen_t],[AC_DEFINE([HAVE_SOCKLEN_T],[1],[socklen_t])],,[
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

AC_OUTPUT
