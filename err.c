/* (c) 2006, Quest Software, Inc. All rights reserved. */

#include "common.h"
#include "err.h"

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#define ERR	1
#define WARN	0
#define X	2

#ifndef va_copy
# define va_copy(x,y) (x) = (y)
#endif

static void _err(int exitcode, int flags, const char *fmt, va_list ap);

static int syslog_enabled = 0;

void
err_enable_syslog(int enabled)
{
    syslog_enabled = enabled;
}

static void
_err(int exitcode, int flags, const char *fmt, va_list ap)
{
    int save_errno = errno;
#if HAVE_VSYSLOG
    va_list ap2;
    char fmt2[8192];
#endif

#if HAVE_VSYSLOG
    if (syslog_enabled) {
	va_copy(ap2, ap);
	if ((flags & X) == 0) {
	    snprintf(fmt2, sizeof fmt2, "%s: %%m", fmt);
	    fmt = fmt2;
	}
    }
#endif

    fprintf(stderr, "%s: ",
	    (flags & ERR) ? "error" : "warning");
    vfprintf(stderr, fmt, ap);
    if ((flags & X) == 0)
	fprintf(stderr, ": %s", strerror(save_errno));
    fprintf(stderr, "\n");

#if HAVE_VSYSLOG
    if (syslog_enabled) {
	errno = save_errno;
	vsyslog(LOG_DAEMON | ((flags & ERR) ? LOG_ERR : LOG_WARNING), fmt, ap2);
    }
#endif

    if (flags & ERR)
	exit(exitcode);
}

void
errx(int exitcode, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR|X, fmt, ap);
}

void
err(int exitcode, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR, fmt, ap);
}

void
warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN|X, fmt, ap);
    va_end(ap);
}

void
warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN, fmt, ap);
    va_end(ap);
}
