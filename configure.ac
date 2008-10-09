# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([dnsupdate],
	[1.3.1.]esyscmd(svnversion -n . /trunk || echo 0),
	[support@quest.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([dnsupdate.c])
AC_CONFIG_FILES([Makefile ipwatchd/Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])
AC_SUBST([mandir], ['${prefix}/man'])

AC_PROG_CC
AC_PROG_SED
AC_C_CONST
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([netdb.h unistd.h sys/socket.h errno.h netinet/in.h fcntl.h])
AC_CHECK_HEADERS([signal.h syslog.h sys/un.h sys/types.h sys/wait.h sys/poll.h])
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h])

AC_PATH_PROG([VASCONFIG], [vas-config], [no], [/opt/quest/bin:$PATH])
if test x"$VASCONFIG" = x"no"; then
    AC_MSG_ERROR([vas-config was not found; is the VAS SDK installed?])
fi
AC_SUBST([VASCONFIG])

AC_PROG_LN_S
AC_PATH_PROG([WGET], [wget], [false])
AC_SUBST([WGET])
AC_PATH_PROG([CURL], [curl], [false])
AC_SUBST([CURL])

AC_CHECK_FUNC([getaddrinfo])
AC_CHECK_FUNC([vsyslog])
AC_CHECK_FUNC([getopt], [], [AC_LIBOBJ([getopt])])
dnl AC_CHECK_FUNCS([err errx warn warnx], [], [AC_LIBOBJ([err]) ; break])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_CHECK_FUNC([socketpair])
AC_FUNC_FORK

AC_CHECK_TYPE([socklen_t],[AC_DEFINE([HAVE_SOCKLEN_T],[1],[socklen_t])],,[
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_TYPE_SIGNAL
AC_CANONICAL_HOST
AC_MSG_CHECKING([ipwatchd needed])
case $host in
	*-*-darwin*)   with_ipwatchd=yes;;
	*)	       with_ipwatchd=no;;
esac
AC_MSG_RESULT($with_ipwatchd)
WITH_IPWATCHD=$with_ipwatchd
AC_SUBST([WITH_IPWATCHD])
AM_CONDITIONAL([WITH_IPWATCHD], test $with_ipwatchd = yes)

AC_OUTPUT
