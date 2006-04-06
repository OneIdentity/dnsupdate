/* (c) 2006, Quest Software Inc. All rights reserved. */
/* David Leonard, 2006 */

#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "dns.h"
#include "dnstcp.h"

/*
 * DNS over TCP
 * These functions provide a very simple way of connecting to
 * a domain name server using TCP. 
 * UDP is not supported.
 */

static int  tcp_connect(const char *host, const char *service);

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

/* 
 * Connects to a DNS server using TCP. 
 * Returns a socket decsriptor or -1 on error.
 */
int
dnstcp_connect(const char *host)
{
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
    if (write(s, b, sizeof b) != 2) {
	warn("write");
	return -1;
    }
    if (len > 0 && write(s, buf, len) != len) {
	warn("write");
	return -1;
    }
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

    for (pos = 0; pos < sizeof b; pos += len) {
	len = read(s, b + pos, sizeof b - pos);
	if (len < 0) {
	    warn("read");
	    return -1;
	}
	if (len == 0) {
	    if (pos) warn("close after short read");
	    return 0;
	}
	/* fprintf(stderr, "[read %d of %d header]\n", pos+len, sizeof b); */
    }

    msglen = (b[0] << 8) | b[1];
    if (msglen > bufsz) {
	warn("buffer too small");
	return -1;
    }
    for (pos = 0; pos < msglen; pos += len) {
	if ((len = read(s, buf + pos, msglen - pos)) < 0) {
	    warn("read");
	    return -1;
	}
	if (len == 0) {
	    warn("close after short read");
	    return 0;
	}
	/* fprintf(stderr, "[read %d of %d]\n", pos+len, msglen); */
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

