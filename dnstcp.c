/* (c) 2006, Quest Software Inc. All rights reserved. */
/* David Leonard, 2006 */

#include "common.h"

#if HAVE_SIGNAL_H
# include <signal.h>
#endif

#include "err.h"
#include "dns.h"
#include "dnstcp.h"
#include <sys/un.h>

/*
 * DNS over TCP
 * These functions provide a very simple way of connecting to
 * a domain name server using TCP. 
 * UDP is not supported.
 */

static int  tcp_connect(const char *host, const char *service);
extern int verbose;

#if HAVE_GETADDRINFO
/* Connects to a TCP service. Returns socket descriptor or -1 on failure. */
static int
tcp_connect(const char *host, const char *service)
{
    struct addrinfo hints, *res, *res0;
    int error, s;
    const char *cause;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(host, service, &hints, &res0);
    if (error) {
	warnx("%s", gai_strerror(error));
	return -1;
    }
    s = -1;
    for (res = res0; res; res = res->ai_next) {
	s = socket(res->ai_family, res->ai_socktype,
	    res->ai_protocol);
	if (s < 0) {
	    cause = "socket";
	    continue;
	}
	if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
	    cause = "connect";
	    close(s);
	    s = -1;
	    continue;
	}
	break;  /* success */
    }
    if (s < 0)
	warn("%s", cause);
    freeaddrinfo(res0);

    return s;
}

#else /* ! HAVE_GETADDRINFO */

# if HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif

static int
tcp_connect(const char *host, const char *service)
{
    struct servent *servent;
    struct hostent *hostent;
    struct sockaddr_in sin;
    int s;

    servent = getservbyname(service, "tcp");
    if (!servent) {
	warnx("unknown service tcp/%s", service);
	return -1;
    }

    hostent = gethostbyname(host);
    if (!hostent) {
	warnx("unknown host %s", host);
	return -1;
    }
    assert(hostent->h_addrtype == AF_INET);
    assert(hostent->h_length == sizeof sin.sin_addr);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	warn("socket");
	return -1;
    }
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = servent->s_port;	/* htons()?? */
    memcpy(&sin.sin_addr, hostent->h_addr, sizeof sin.sin_addr);

    if (verbose > 2)
	fprintf(stderr, "connecting to port %u\n", servent->s_port);

    if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
	warn("connect");
	close(s);
	return -1;
    }

    return s;
}

#endif /* ! HAVE_GETADDRINFO */

static int
unix_connect(const char *local)
{
    int s;
    struct sockaddr_un sun;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
	warn("socket");
	return -1;
    }
    memset(&sun, 0, sizeof sun);
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof sun.sun_path, "%s", local);
    if (verbose > 2)
	fprintf(stderr, "connecting to unix socket %s\n", sun.sun_path);
    if (connect(s, (struct sockaddr *)&sun, sizeof sun) < 0) {
	warn("connect");
	close(s);
	return -1;
    }
    return s;
}

/*
 * Connects to a local domain address, and sends the intended hostname
 * as a string preceded by a 16-bit length
 */
static int
debug_connect_unix(const char *local, const char *host)
{
    int s;

    if ((s = unix_connect(local)) < 0)
	return -1;

    /* Write the target hostname preceded by a 16-bit length */
    dnstcp_send(s, host, strlen(host));

    return s;
}

/*
 * Forks a wrapper program, setting up a TCP-like socket for communication
 */
static int
debug_connect_exec(const char *wrapper, const char *host)
{
    int sp[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
	warn("socketpair");
	return -1;
    }

    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
	warn("signal SIGCHLD");

    switch (fork()) {
    case -1:
	warn("fork");
	close(sp[0]);
	close(sp[1]);
	return -1;
    default:
	/* parent */
	close(sp[1]);
	return sp[0];
    case 0:
	/* child */
	if (verbose)
	    fprintf(stderr, "starting wrapper pid %d: %s %s\n", 
		    getpid(), wrapper, host);
	close(sp[0]);
	if (sp[1] != 0) {
	    if (close(0) < 0)
		warn("close 0");
	    if (dup2(sp[1], 0) < 0)
		warn("dup2 0");
	}
	if (sp[1] != 1) {
	    if (close(1) < 0)
		warn("close 1");
	    if (dup2(sp[1], 1) < 0)
		warn("dup2 1");
	}
	if (sp[1] != 0 && sp[1] != 1)
	    close(sp[1]);
	execlp(wrapper, wrapper, host, NULL);
	warn("%s", wrapper);
	_exit(1);
	/* NOTREACHED */
    }
}

static struct {
    const char *label;
    int (*connect)(const char *where, const char *host);
} debug_intercepts[] = {
    { "unix:", debug_connect_unix },
    { "exec:", debug_connect_exec }
};

#ifndef lengthof
# define lengthof(a) (sizeof a / sizeof a[0])
#endif

/* 
 * Connects to a DNS server using TCP. 
 * Returns a socket decsriptor or -1 on error.
 */
int
dnstcp_connect(const char *host)
{
    char *intercept;

    intercept = getenv("DNSTCP_CONNECT_INTERCEPT");
    if (intercept && *intercept) {
	int i;
	for (i = 0; i < lengthof(debug_intercepts); i++)
	    if (memcmp(intercept, debug_intercepts[i].label, 
		    strlen(debug_intercepts[i].label)) == 0)
		return (*debug_intercepts[i].connect)(
			intercept + strlen(debug_intercepts[i].label),
			host);
	errx(1, "dnstcp_connect: bad prefix in DNSTCP_CONNECT_INTERCEPT: %s",
		intercept);
    }
    return tcp_connect(host, "domain");
}

/*
 * Sends data on a TCP/DNS connection preceded by uint16 length;
 * Returns len or -1 on error.
 */
int
dnstcp_send(int s, const void *buf, size_t len)
{
    unsigned char b[2];
    assert(len <= 0xffff);

    b[0] = (len >> 8) & 0xff;
    b[1] = len & 0xff;

#if PACK_DNSTCP_SEND
    {
	/* There is a bug in wireshark's TCP/DNS decoder. This is 
	 * temporary to get around it. */
	/* See http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=2272 */
	char *tbuf = malloc(len + 2);
	memcpy(tbuf, b, 2);
	memcpy(tbuf + 2, buf, len);
	if (write(s, tbuf, len + 2) != len + 2) {
	    warn("write");
	    free(tbuf);
	    return -1;
	}
	free(tbuf);
    }
#else
    if (verbose > 3) 
	fprintf(stderr, "dnstcp_send: writing length %02x %02x\n", b[0], b[1]);
    if (write(s, b, sizeof b) != 2) {
	warn("write");
	return -1;
    }
    if (verbose > 3) 
	fprintf(stderr, "dnstcp_send: writing %d bytes to fd %d\n", 
		(int)len, s);
    if (len > 0 && write(s, buf, len) != len) {
	warn("write");
	return -1;
    }
#endif
    return len;
}

void
dnstcp_close(int *s)
{
    if (close(*s) == -1)
	warn("close");
    *s = -1;
}

/* 
 * Receives data from a TCP/DNS connection; 
 * Reads a uint16 length and then reads the subsequent data
 * into the buffer provided.
 * Retries/aborts on error or too-small buffer
 * Returns length of data read (excluding length header), or
 * -1 on error.
 */
int
dnstcp_recv(int s, void *buf, size_t bufsz)
{
    unsigned char b[2];
    int len, msglen;
    int pos;

    if (verbose > 3)
	fprintf(stderr, "dnstcp_recv s %d buf %p bufsz %d\n", 
		s, buf, (int)bufsz);

    for (pos = 0; pos < sizeof b; pos += len) {
	len = read(s, b + pos, sizeof b - pos);
	if (verbose > 3)
	    fprintf(stderr, "  header read -> %d\n", len);
	if (len < 0) {
	    warn("read");
	    return -1;
	}
	if (len == 0) {
	    if (pos) warn("close after short read");
	    return 0;
	}
        if (verbose > 3)
	   fprintf(stderr, "[read %d of %d header]\n", pos+len, 
		   (int)sizeof b);
    }

    if (verbose > 3)
	fprintf(stderr, "  header %02x %02x\n", b[0], b[1]);

    msglen = (b[0] << 8) | b[1];
    if (msglen > bufsz) {
	warn("buffer too small");
	return -1;
    }
    for (pos = 0; pos < msglen; pos += len) {
	if ((len = read(s, (char *)buf + pos, msglen - pos)) < 0) {
	    warn("read");
	    return -1;
	}
	if (len == 0) {
	    warn("close after short read");
	    return 0;
	}
        if (verbose > 3)
	    fprintf(stderr, "[read %d of %d]\n", pos+len, msglen);
    }
    return msglen;
}

int
dnstcp_sendmsg(int s, const struct dns_msg *msg)
{
    void *base;
    size_t len;
    
    dns_msg_getbuf(msg, &base, &len);
    return dnstcp_send(s, base, len);
}

int
dnstcp_recvmsg(int s, void *buf, size_t bufsz, struct dns_msg *msg)
{
    int len;

    len = dnstcp_recv(s, buf, bufsz);
    if (len >= 0)
	dns_msg_setbuf(msg, buf, len);
    return len;
}

