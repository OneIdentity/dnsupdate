
#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <assert.h>
# include <stddef.h>
# include <stdarg.h>
#else
# if !HAVE_MEMCPY
#  define memcpy(d, s, n)  bcopy(s, d, n)
# endif
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_FCNTL_H
# include <fcntl.h>
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#if HAVE_ERRNO_H
# include <errno.h>
#endif

#if !HAVE_SOCKLEN_T
# define socklen_t int
#endif
