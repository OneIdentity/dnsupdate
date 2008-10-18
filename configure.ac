# (c) 2006 Quest Software, Inc. All rights reserved.

AC_INIT([dnsupdate],
	[1.3.1.]esyscmd(svnversion -n . /trunk || echo 0),
	[support@quest.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([dnsupdate.c])
AC_CONFIG_FILES([Makefile ipwatchd/Makefile])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/opt/quest])
# Note: these directory changes makes the --help output wrong
AC_SUBST([mandir], ['${prefix}/man'])
AC_SUBST([sysconfdir], ['/etc${prefix}'])

AC_PROG_SED

# look for Apple's universal binary support
AC_PROG_CC
AC_ARG_ENABLE([universal-binary],
	      [AC_HELP_STRING([--enable-universal-binary=auto],
			      [Apple universal binary support])],,
	      [enable_universal_binary=auto])
have_universal_binary=no
if test x"$enable_universal_binary" != x"no"; then
    AC_CANONICAL_HOST
    AC_MSG_CHECKING([for universal binary support])
    case $host in *-apple-darwin*)
       mysave_CFLAGS="$CFLAGS"
       mysave_CFLAGS="$LDFLAGS"
       CFLAGS="$CFLAGS -arch ppc -arch i386"
       LDFLAGS="$LDFLAGS -arch ppc -arch i386"
       AC_LINK_IFELSE([int main(){return 0;}],[have_universal_binary=yes])
       if test $have_universal_binary = no; then
	   LDFLAGS="$mysave_LDFLAGS"
	   CFLAGS="$mysave_CFLAGS"
       fi
    esac
    AC_MSG_RESULT($have_universal_binary)
fi
case "$have_universal_binary:$enable_universal_binary" in
    no:yes) AC_MSG_ERROR([no universal binary support on this host]) ;;
    yes:*)  AC_MSG_WARN([disabling dependency tracking])
	    AM_CONDITIONAL([AMDEP],[false])	    # automake-1.9.6
	    AM_CONDITIONAL([am__fastdep],[false])
	    AM_CONDITIONAL([am__fastdepCC],[false])
	    AMDEPBACKSLASH=
	    ;;
esac

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
