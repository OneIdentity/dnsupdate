#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "err.h"

#define ERR	1
#define WARN	0
#define X	2

static void _err(int exitcode, int flags, const char *fmt, va_list ap);

static void
_err(int exitcode, int flags, const char *fmt, va_list ap)
{
    fprintf(stderr, "%s: ",
	    (flags & ERR) ? "error" : "warning");
    vfprintf(stderr, fmt, ap);
    if ((flags & X) == 0)
	fprintf(stderr, ": %s", strerror(errno));
    fprintf(stderr, "\n");
}

void
errx(int exitcode, const char *fmt)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR|X, fmt, ap);
}

void
err(int exitcode, const char *fmt)
{
    va_list ap;
    va_start(ap, fmt);
    _err(exitcode, ERR, fmt, ap);
}

void
warnx(const char *fmt)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN|X, fmt, ap);
    va_end(ap);
}

void
warn(const char *fmt)
{
    va_list ap;
    va_start(ap, fmt);
    _err(0, WARN, fmt, ap);
    va_end(ap);
}
