/* (c) 2006 Quest Software, Inc. All rights reserved. */
/* David Leonard, 2006 */

#include "common.h"
#include "dns.h"

/*
 * Functions for decoding DNS packets (RFC 1035)
 *
 * NOTE: The dns_msg structure is used for both reading
 * and writing. You have to decide which mode you're going
 * to use it in. In read mode, the buffer size is used as a
 * read limit, and the position pointer is where future reads
 * will occur. In write mode, the buffer size is a write limit, 
 * and the position pointer marks where the end of the written
 * data is (and/or where the next write will occur).
 *
 * Both read and write have begin/end nesting functions, which
 * are used to help with segments of the form { uint16 length; octet[] data }
 * The read versions temporarily 'stack' the read limit so that
 * over-reads can be detected. The write version requires the caller
 * to provide stack storage [XXX bad: both should do the same thing]
 *
 * Error handling is done by simply calling the error handling function
 * that you can set. Errors in parsing packets generally indicate 
 * unrecoverable failure. [XXX The DNS protocols generally want the
 * peer to send back error packets, so this should be rethought]
 */

/* Prototypes */
static void check(struct dns_msg *msg, uint16_t len);
static void rd_error(const char *msg);
static void rd_name(struct dns_msg *msg, char *buf, size_t bufsz, 
	int canon_only);
static void wr_label(struct dns_msg *msg, int len, const char *name);
static void wr_name(struct dns_msg *msg, const char *name, int compress);

static void (*error_handler)(const char *, void *);
static void *error_handler_closure;
int dns_never_compress = 0;

/* Creates a new message with a zero-sized buffer */
struct dns_msg *
dns_msg_new()
{
    struct dns_msg *msg;

    msg = (struct dns_msg *)malloc(sizeof (struct dns_msg));
    if (msg) {
	memset(msg, 0, sizeof msg);
    }
    return msg;
}

/* Releases a message structure */
void
dns_msg_free(struct dns_msg *msg)
{
    free(msg);
}

/* Sets the buffer used by a message */
void
dns_msg_setbuf(struct dns_msg *msg, void *buf, size_t sz)
{
    assert(sz <= 0xffff);
    msg->remain[0] = (uint16_t)sz;
    msg->data = buf;
    msg->depth = 0;
    msg->pos = 0;
    msg->namecachelen = 0;
}

/* Reads the header data from the message buffer into header */
void
dns_rd_header(struct dns_msg *msg, struct dns_header *header)
{
    uint16_t flags;
    header->id = dns_rd_uint16(msg);
    flags = dns_rd_uint16(msg);
    header->response            = (flags >> 15) & 1;
    header->opcode              = (flags >> 11) & 0xf;
    header->authoritative       = (flags >> 10) & 1;
    header->truncated           = (flags >>  9) & 1;
    header->recurse_desired     = (flags >>  8) & 1;
    header->recurse_avail       = (flags >>  7) & 1;
    header->rcode               = (flags >>  0) & 0xf;
    header->qdcount = dns_rd_uint16(msg);
    header->ancount = dns_rd_uint16(msg);
    header->nscount = dns_rd_uint16(msg);
    header->arcount = dns_rd_uint16(msg);
}

/* Writes header into the message buffer */
void
dns_wr_header(struct dns_msg *msg, const struct dns_header *header)
{
    uint16_t flags = 0;

    dns_wr_uint16(msg, header->id);
    flags |= header->response        << 15;
    flags |= header->opcode          << 11;
    flags |= header->authoritative   << 10;
    flags |= header->truncated       <<  9;
    flags |= header->recurse_desired <<  8;
    flags |= header->recurse_avail   <<  7;
    flags |= header->rcode           <<  0;
    dns_wr_uint16(msg, flags);
    dns_wr_uint16(msg, header->qdcount);
    dns_wr_uint16(msg, header->ancount);
    dns_wr_uint16(msg, header->nscount);
    dns_wr_uint16(msg, header->arcount);
}

/* Exits with an error message */
static void
rd_error(const char *msg)
{
    if (error_handler)
	(*error_handler)(msg, error_handler_closure);
    fprintf(stderr, "%s\n", msg);
    assert(0);
    exit(1);
}

/* Sets the error handler */
void
dns_set_error_handler(void (*handler)(const char *, void *), void *closure)
{
    error_handler = handler;
    error_handler_closure = closure;
}

/* Checks that a read/write will not exceed the message bounds */
static void
check(struct dns_msg *msg, uint16_t len)
{
    if (msg->remain[msg->depth] < len)
	rd_error("read/write beyond bounds");
}

/* Skips data in a readable message */
void
dns_rd_skip(struct dns_msg *msg, uint16_t len)
{
    check(msg, len);
    msg->remain[msg->depth] -= len;
    msg->pos += len;
}

/* Reads raw data from the message buffer into the user buffer */
void
dns_rd_data_raw(struct dns_msg *msg, void *buf, uint16_t bufsz)
{
    check(msg, bufsz);
    memcpy(buf, (unsigned char *)msg->data + msg->pos, bufsz);
    msg->pos += bufsz;
    msg->remain[msg->depth] -= bufsz;
}

/* Reads a uint16_t followed by raw data from the msg buffer into a user buf */
uint16_t
dns_rd_data(struct dns_msg *msg, void *buf, size_t bufsz)
{
    uint16_t len = dns_rd_uint16(msg);
    if (len > bufsz)
	rd_error("data too large for buffer");
    dns_rd_data_raw(msg, buf, len);
    return len;
}

/* Reads a uint16_t length, stores pointer to data in buffer and skips it */
uint16_t
dns_rd_datap(struct dns_msg *msg, void **ptr)
{
    uint16_t len = dns_rd_uint16(msg);
    *ptr = (unsigned char *)msg->data + msg->pos;
    dns_rd_skip(msg, len);
    return len;
}

/* Reads a uint16_t from the msg buffer */
uint16_t
dns_rd_uint16(struct dns_msg *msg)
{
    unsigned char b[2];
    dns_rd_data_raw(msg, b, sizeof b);
    return (b[0] << 8) | b[1];
}

/* Reads a uint32_t from the msg buffer */
uint32_t
dns_rd_uint32(struct dns_msg *msg)
{
    unsigned char b[4];
    dns_rd_data_raw(msg, b, sizeof b);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | (b[3] << 0);
}

/* Reads an int32_t from the msg buffer */
int32_t
dns_rd_int32(struct dns_msg *msg)
{
    return (int32_t)dns_rd_uint32(msg);
}

/* Reads the head part of a resource record from a msg buffer */
void
dns_rd_rr_head(struct dns_msg *msg, struct dns_rr *rr)
{
    dns_rd_name(msg, rr->name, sizeof rr->name);
    rr->type = dns_rd_uint16(msg);
    rr->class_ = dns_rd_uint16(msg);
    rr->ttl = dns_rd_int32(msg);
}

void
dns_rd_question(struct dns_msg *msg, struct dns_rr *rr)
{
    dns_rd_name(msg, rr->name, sizeof rr->name);
    rr->type = dns_rd_uint16(msg);
    rr->class_ = dns_rd_uint16(msg);
    rr->ttl = 0;
}

/* Writes the head of an RR record into the packet. 
 * This call should be followed by a call to dns_wr_data() 
 * or to dns_wr_begin().
 */
void
dns_wr_rr_head(struct dns_msg *msg, const struct dns_rr *rr)
{
    dns_wr_name(msg, rr->name);
    dns_wr_uint16(msg, rr->type);
    dns_wr_uint16(msg, rr->class_);
    dns_wr_int32(msg, rr->ttl);
}

/* Makes space for a uint16_t, stores its offset into mark */
void
dns_wr_begin(struct dns_msg *msg, uint16_t *mark)
{
    check(msg, 2);
    *mark = msg->pos;
    msg->pos += 2;
    msg->remain[msg->depth] -= 2;
}

/*
 * Completes data writen after a dns_wr_begin().
 * Works by updating the length field that was skipped by
 * the call to dns_wr_begin()
 */
void
dns_wr_end(struct dns_msg *msg, uint16_t *mark)
{
    uint16_t len = msg->pos - *mark - 2;
    ((unsigned char *)msg->data)[*mark] = (len >> 8) & 0xff;
    ((unsigned char *)msg->data)[*mark + 1] = (len >> 0) & 0xff;
}

/* Writes a question record (ie an RR without the TTL field) */
void
dns_wr_question(struct dns_msg *msg, const struct dns_rr *rr)
{
    dns_wr_name(msg, rr->name);
    dns_wr_uint16(msg, rr->type);
    dns_wr_uint16(msg, rr->class_);
}

/* Reads a uint16_t and pushes a read boundary marker */
void
dns_rd_begin(struct dns_msg *msg)
{
    dns_rd_begin_raw(msg, dns_rd_uint16(msg));
}

/* Pushes a read boundary marker */
void
dns_rd_begin_raw(struct dns_msg *msg, uint16_t len)
{
    check(msg, len);
    msg->remain[msg->depth] -= len;
    msg->depth++;
    msg->remain[msg->depth] = len;
}

/* Skips to the next boundary, and pops the boundary marker */
void
dns_rd_end(struct dns_msg *msg)
{
    if (msg->depth == 0)
	rd_error("too many rd_ends");
    dns_rd_skip(msg, msg->remain[msg->depth]);
    msg->depth--;
}

/* Returns the number of bytes remaining until the next boundary */
uint16_t
dns_rd_remain(const struct dns_msg *msg)
{
    return msg->remain[msg->depth];
}

/* Returns the current position */
size_t
dns_msg_getpos(const struct dns_msg *msg)
{
    return msg->pos;
}

/* Sets the current position */
void
dns_rd_setpos(struct dns_msg *msg, size_t pos)
{
    if (pos > msg->pos)
	dns_rd_skip(msg, pos - msg->pos);
    else if (pos < msg->pos) {
	msg->remain[msg->depth] += (msg->pos - pos);
	msg->pos = pos;
    }
}

/* Returns the data remaining to be read */
void
dns_msg_getbuf(const struct dns_msg *msg, void **bufp, size_t *szp)
{
    unsigned char *p = (unsigned char *)msg->data;

    *bufp = p + msg->pos;
    *szp = dns_rd_remain(msg);
}

/*
 * Reads a domain name from the buffer. Automatically decompresses.
 * The buffer is filled in with dot (.) used as a delimiter
 */
static void
rd_name(struct dns_msg *msg, char *buf, size_t bufsz, int canon_only)
{
    unsigned char b, b2;
    char *p = buf;
    char *pend = buf + bufsz - 1;
    uint16_t pos_save = 0;
    uint16_t remain_save = 0;
    uint16_t offset;
    uint16_t pointers = 0;
#define MAXPOINTERS 32768

    if (bufsz < 1) 
	goto toosmall;

    for (;;) {
	dns_rd_data_raw(msg, &b, sizeof b);
	if (b == 0)		/* End of label chain */
	    break;
	if ((b & 0xc0) != 0xc0) {
	    if (p != buf) {	/* Append period delimiter */
		if (p >= pend) goto toosmall;
		*p++ = '.';
	    }
	    if (p + b >= pend) goto toosmall;
	    dns_rd_data_raw(msg, p, b);
	    p += b;
	} else {		/* compression pointer */
	    if (canon_only)
		rd_error("invalid name compression");
	    if (pointers++ > MAXPOINTERS)
		rd_error("too much compression");
	    dns_rd_data_raw(msg, &b2, sizeof b2);
	    offset = ((b << 8) | b2) & 0x3fff;
	    if (!pos_save) {
		pos_save = msg->pos;
	        remain_save = msg->remain[msg->depth];
            }
	    if (offset < msg->pos)
		msg->remain[msg->depth] += msg->pos - offset;
	    else if (offset - msg->pos > msg->remain[msg->depth])
		rd_error("compressed name offset bound error");
	    else
		msg->remain[msg->depth] -= offset - msg->pos;
	    msg->pos = offset;
	}
    }
    *p = '\0';
    if (pos_save) {
	msg->pos = pos_save;
	msg->remain[msg->depth] = remain_save;
    }

    return;

toosmall:
    rd_error("name too long for buffer");
}

void
dns_rd_name(struct dns_msg *msg, char *buf, size_t bufsz)
{
    rd_name(msg, buf, bufsz, 0);
}

void
dns_rd_name_canon(struct dns_msg *msg, char *buf, size_t bufsz)
{
    rd_name(msg, buf, bufsz, 1);
}

/* Writes/appends binary data to the packet buffer */
void
dns_wr_data_raw(struct dns_msg *msg, const void *buf, size_t bufsz)
{
    check(msg, bufsz);
    memcpy((unsigned char *)msg->data + msg->pos, buf, bufsz);
    msg->pos += bufsz;
    msg->remain[msg->depth] -= bufsz;
}

/* Writes a uint16 length followed by binary data */
void
dns_wr_data(struct dns_msg *msg, const void *buf, uint16_t len)
{
    dns_wr_uint16(msg, len);
    dns_wr_data_raw(msg, buf, len);
}

/* Writes a 16-bit unsigned integer into the packet buffer */
void
dns_wr_uint16(struct dns_msg *msg, uint16_t val)
{
    unsigned char b[2];
    b[0] = (val >> 8) & 0xff;
    b[1] = (val >> 0) & 0xff;
    dns_wr_data_raw(msg, b, sizeof b);
}

/* Writes a 32-bit unsigned integer into the packet buffer */
void
dns_wr_uint32(struct dns_msg *msg, uint32_t val)
{
    unsigned char b[4];
    b[0] = (val >> 24) & 0xff;
    b[1] = (val >> 16) & 0xff;
    b[2] = (val >>  8) & 0xff;
    b[3] = (val >>  0) & 0xff;
    dns_wr_data_raw(msg, b, sizeof b);
}

/* Writes a 32-bit integer into the packet buffer */
void
dns_wr_int32(struct dns_msg *msg, int32_t val)
{
    dns_wr_uint32(msg, (uint32_t)val);
}

/* Writes a label into a packet (without compression) */
static void
wr_label(struct dns_msg *msg, int len, const char *name)
{
    unsigned char b;

    assert(len < 32);
    b = (unsigned char)len;
    dns_wr_data_raw(msg, &b, sizeof b);
    if (len)
	dns_wr_data_raw(msg, name, len);
}

/* Writes a name into the packet, automatically compressing */
static void
wr_name(struct dns_msg *msg, const char *name, int compress)
{
    int i;
    const char *p;
    unsigned char cachelen = msg->namecachelen;

    assert(strlen(name) < DNS_MAXNAME - 1);

    while (*name) {
	if (*name == '.')
	    rd_error("too many dots in domain name");
	if (compress) {
	    for (i = 0; i < msg->namecachelen; i++)
		if (strcmp(name, msg->namecache[i].name) == 0) {
		    uint16_t offset = msg->namecache[i].offset | 0xc000;
		    dns_wr_uint16(msg, offset);
		    return;
		}
	    strcpy(msg->namecache[cachelen].name, name);
	    msg->namecache[cachelen].offset = msg->pos;
	    cachelen++;
	}
	for (p = name; *p; p++)
	    if (*p == '.') break;
	wr_label(msg, p - name, name);
	name = p;
	if (*name == '.') name++;	/* trailing dot is ok */
    }
    wr_label(msg, 0, NULL);
    msg->namecachelen = cachelen;
}

void
dns_wr_name(struct dns_msg *msg, const char *name)
{
    wr_name(msg, name, dns_never_compress ? 0 : 1);
}

void
dns_wr_name_canon(struct dns_msg *msg, const char *name)
{
    wr_name(msg, name, 0);
}

/* Increments the arcount, in situ */
static void
inc_count(struct dns_msg *msg, int offset)
{
    uint16_t count;
    unsigned char *p;

    assert(msg->pos >= 12);	/* header must be present */
    assert(offset < 12);	/* offset must be inheader */
    assert((offset & 1) == 0);	/* offset must be 16-bit aligned */
    p = (unsigned char *)msg->data + offset;
    count = p[0] << 8 | p[1];
    count++;
    p[0] = (count >> 8) & 0xff;
    p[1] = count & 0xff;
}

#ifndef offsetof
# define offsetof(T, field) ((int)&((T *)0)->field)
#endif

/* Increments the qdcount, in situ */
void
dns_wr_inc_qdcount(struct dns_msg *msg)
{
    inc_count(msg, offsetof(struct dns_header, qdcount));
}

/* Increments the ancount, in situ */
void
dns_wr_inc_ancount(struct dns_msg *msg)
{
    inc_count(msg, offsetof(struct dns_header, ancount));
}

/* Increments the nscount, in situ */
void
dns_wr_inc_nscount(struct dns_msg *msg)
{
    inc_count(msg, offsetof(struct dns_header, nscount));
}

/* Increments the arcount, in situ */
void
dns_wr_inc_arcount(struct dns_msg *msg)
{
    inc_count(msg, offsetof(struct dns_header, arcount));
}

/* Decrements the arcount, in situ. UNCHECKED */
void
dns_rd_dec_arcount(struct dns_msg *msg)
{
    uint16_t arcount;
    unsigned char *p;

    p = (unsigned char *)&(((struct dns_header *)msg->data)->arcount);
    arcount = p[0] << 8 | p[1];
    arcount--;
    p[0] = (arcount >> 8) & 0xff;
    p[1] = arcount & 0xff;
}

void
dns_wr_finish(struct dns_msg *msg)
{
    dns_msg_setbuf(msg, msg->data, msg->pos);
}

void
dns_rr_set_name(struct dns_rr *rr, const char *name)
{
    int len = strlen(name);
    if (len + 1 > sizeof rr->name)
	rd_error("dns_rr_set_name: name too long");
    memcpy(rr->name, name, len + 1);
}

const char *
dns_rcode_name(uint16_t rcode)
{
    static struct { uint16_t rcode; const char *desc; } desc[] = {
	{ DNS_NOERROR,  "no error" },
	{ DNS_FORMERR,  "format error" },
	{ DNS_SERVFAIL, "server failure" },
	{ DNS_NXDOMAIN, "name error" },
	{ DNS_NOTIMP,   "not implemented" },
	{ DNS_REFUSED,  "refused" },
	{ DNS_YXDOMAIN,	"unwanted domain exists" },
	{ DNS_YXRRSET,	"unwanted RRs exist" },
	{ DNS_NXRRSET,	"wanted RRs don't exist" },
	{ DNS_NOTAUTH,	"not authorized" },
	{ DNS_NOTZONE,	"not a zone" },
	{ DNS_BADSIG,   "bad signature" },
	{ DNS_BADKEY,   "bad key" },
	{ DNS_BADTIME,  "bad time" },
	{ DNS_BADMODE,  "bad mode" },
	{ DNS_BADNAME,  "bad name" },
	{ DNS_BADALG,   "bad algorithm" },
    };
    static char buf[64];
    int i;

    for (i = 0; i < sizeof desc / sizeof desc[0]; i++)
	if (desc[i].rcode == rcode)
	    return desc[i].desc;
    snprintf(buf, sizeof buf, "<error %u>", rcode);
    return buf;
}
