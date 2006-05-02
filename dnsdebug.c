/* (c) 2006, Quest Software Inc. All rights reserved */
/* David Leonard, 2006 */

#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "dns.h"
#include "dnsdebug.h"

extern int vflag;

/*
 * Debug/dump routines.
 * These functions double as testing and inspection; they
 * implement their own packet parsers, so to speak.
 */

/* A desc table is an array of 'struct desc' terminated with a NULL desc */
struct desc {
    uint16_t value;
    const char *desc;
};

static const char *desc_lookup(const struct desc *desc, uint16_t value);
static void dumprr_part(const struct dns_rr *rr);
static void dumpheader(const struct dns_header *hdr);
static void dumpquestion(const struct dns_rr *question);


static struct desc opcode_desc[] = {
    { DNS_OP_QUERY,  "query" },
    { DNS_OP_IQUERY, "iquery" },
    { DNS_OP_STATUS, "status" },
    { DNS_OP_UPDATE, "update" },
    { 0, 0 }
};

static struct desc rrtype_desc[] = {
    { DNS_TYPE_A, "A" },
    { DNS_TYPE_NS, "NS" },
    {   3, "MD" },
    {   4, "MF" },
    {   5, "CNAME" },
    { DNS_TYPE_SOA, "SOA" },
    {   7, "MB" },
    {   8, "MG" },
    {   9, "MR" },
    { DNS_TYPE_NULL, "NULL" },
    {  11, "WKS" },
    { DNS_TYPE_PTR, "PTR" },
    {  13, "HINFO" },
    {  14, "MINFO" },
    {  15, "MX" },
    { DNS_TYPE_TXT, "TXT" },
    { DNS_TYPE_TKEY, "TKEY" },
    { DNS_TYPE_TSIG, "TSIG" },
    { DNS_TYPE_ANY, "*" },
    {   0, 0 }
};

static struct desc rrclass_desc[] = {
    { DNS_CLASS_IN, "IN" },
    {   2, "CSNET" },
    {   3, "CHAOS" },
    {   4, "HESIOD" },
    { 252, "AXFR" },
    { 253, "MAILB" },
    { 254, "MAILA" },
    { DNS_CLASS_ANY, "ANY" },
    {   0, 0 }
};

/* Returns a description. Note returns shared static storage sometimes */
static const char *
desc_lookup(const struct desc *desc, uint16_t value)
{
    const struct desc *d;
    static char descbuf[30];

    if (!desc) return 0;
    for (d = desc; d->desc; d++)
       if (d->value == value)
	   return d->desc;
    snprintf(descbuf, sizeof descbuf, "<0x%x>", value);
    return descbuf;
}

void
dumphex(const void *buf, size_t len)
{
    const unsigned char *data = (const unsigned char *)buf;
    size_t i, j;

    for (i = 0; i < len; i += 16) {
	printf(" %04x:", (int)i);
	for (j = i; j < i + 16; j++) {
	    if (j < len)
		printf(" %02x", data[j]);
	    else
		printf("   ");
	    if (j == i + 7)
		putchar(' ');
	}

	printf("   ");
	for (j = i; j < i + 16 && j < len; j++) {
	    if (data[j] < ' ' || data[j] >= 0x7f)
		putchar('.');
	    else
		putchar(data[j]);
	    if (j == i + 7)
		putchar(' ');
	}
	putchar('\n');
    }

}

static void
dumpdata(struct dns_msg *msg, const char *name, uint16_t len)
{
    unsigned char *p;
   
    p = (unsigned char *)msg->data + dns_msg_getpos(msg);
    dns_rd_skip(msg, len);
    printf("\t%-20s: (len=%d)\n", name, len);
    dumphex(p, len);
}

static void
dumpname(struct dns_msg *msg, const char *name)
{
    char buf[256];
    dns_rd_name(msg, buf, sizeof buf);
    printf("\t%-20s: %s\n", name, buf);
}

static void
dumpuint16(struct dns_msg *msg, const char *name)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    printf("\t%-20s: %u (0x%x)\n", name, v, v);
}

static void
dumpuint16desc(struct dns_msg *msg, const char *name, struct desc *desc)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    printf("\t%-20s: %s (%u)\n", name, desc_lookup(desc, v), v);
}

static void
dumpuint16rcode(struct dns_msg *msg, const char *name)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    printf("\t%-20s: %s\n", name, dns_rcode_name(v));
}

static void
dumpuint32(struct dns_msg *msg, const char *name)
{
    uint32_t v;
    v = dns_rd_uint32(msg);
    printf("\t%-20s: %u (0x%x)\n", name, v, v);
}

static void
dumpuint32time(struct dns_msg *msg, const char *name)
{
    uint32_t v;
    time_t t;
    v = dns_rd_uint32(msg);
    t = (time_t)v;
    printf("\t%-20s: %.24s (0x%x)\n", name, ctime(&t), v);
}

static void
dumpheader(const struct dns_header *hdr)
{
    printf("    header:\n");
    printf("\t%-20s: 0x%04x\n", "id", hdr->id);
    printf("\t%-20s: %s\n", "response", hdr->response ? "RESPONSE" : "QUERY");
    printf("\t%-20s: %s\n", "opcode", desc_lookup(opcode_desc, hdr->opcode));
    printf("\t%-20s: %s\n", "authoritative", hdr->authoritative ? "yes" : "no");
    printf("\t%-20s: %s\n", "truncated", hdr->truncated ? "yes" : "no");
    printf("\t%-20s: %s\n", "recurse-desired", 
	    hdr->recurse_desired ? "yes" : "no");
    printf("\t%-20s: %s\n", "recurse-avail", hdr->recurse_avail ? "yes" : "no");
    printf("\t%-20s: %s (%u)\n", "rcode", 
	    dns_rcode_name(hdr->rcode), hdr->rcode);
    printf("\t%-20s: %u\n", "qdcount", hdr->qdcount);
    printf("\t%-20s: %u\n", "ancount", hdr->ancount);
    printf("\t%-20s: %u\n", "nscount", hdr->nscount);
    printf("\t%-20s: %u\n", "arcount", hdr->arcount);
}


static void
dumprr_part(const struct dns_rr *rr)
{
    printf("\t%-20s: \"%s\"\n", "name", rr->name);
    printf("\t%-20s: %s (%u)\n", "type", 
	    desc_lookup(rrtype_desc, rr->type), rr->type);

    printf("\t%-20s: %s (%u)\n", "class", 
	    desc_lookup(rrclass_desc, rr->class_), rr->class_);

}

void
dumprr(const struct dns_rr *rr, const char *name)
{
    printf("    %s:\n", name);
    dumprr_part(rr);
    printf("\t%-20s: %ld sec\n", "ttl", (long)rr->ttl);
}

static void
dumpquestion(const struct dns_rr *question)
{
    printf("    question:\n");
    dumprr_part(question);
}


void
dumpmsg(struct dns_msg *msg)
{
    char data[32768];
    struct dns_rr rr;
    struct dns_header header;
    int i;
    uint16_t len;
    const char *section;

    void *bufsave;
    size_t bufszsave;

    printf("-------\n");

    assert(dns_msg_getpos(msg) == 0);
    dns_msg_getbuf(msg, &bufsave, &bufszsave);
    if (vflag > 2)
	dumphex(bufsave, bufszsave);

    dns_rd_header(msg, &header);
    dumpheader(&header);
    for (i = 0; i < header.qdcount; i++) {
	dns_rd_question(msg, &rr);
	dumpquestion(&rr);
    }

    for (;;) {
	if (header.ancount) { section = "answer"; header.ancount--; }
	else if (header.nscount) { section = "authority"; header.nscount--; }
	else if (header.arcount) { section = "additional"; header.arcount--; }
	else break;

	dns_rd_rr_head(msg, &rr);
	dumprr(&rr, section);
	if (rr.type == 250) {
	    uint16_t timehi;
	    uint32_t timelo;
	    time_t t;

	    dns_rd_begin(msg);
	    dumpname(msg, "tsig.algorithm");
	    timehi = dns_rd_uint16(msg);
	    timelo = dns_rd_uint32(msg);
	    t = timehi << 32 | timelo;
	    printf("\t%-20s: 0x%x:%08x (%.24s)\n", "tsig.time",
		    	timehi, timelo, ctime(&t));
	    dumpuint16(msg, "tsig.fudge");
	    dumpdata(msg, "tsig.mac", dns_rd_uint16(msg));
	    dumpuint16(msg, "tsig.orig_id");
	    dumpuint16rcode(msg, "tsig.error");
	    dumpdata(msg, "tsig.other", dns_rd_uint16(msg));
	    dns_rd_end(msg);
	} else if (rr.type == 249) {
	    static struct desc modetab[] = {
		{1, "server assignment"},
		{2, "Diffie-Hellman exchange"},
		{3, "GSS-API negotation"},
		{4, "resolver assignment"},
		{5, "key deletion"},
		{0, 0}
	    };
	    dns_rd_begin(msg);
	    dumpname(msg, "tkey.algorithm");
	    dumpuint32time(msg, "tkey.inception");
	    dumpuint32time(msg, "tkey.expiration");
	    dumpuint16desc(msg, "tkey.mode", modetab);
	    dumpuint16rcode(msg, "tkey.error");
	    dumpdata(msg, "tkey.key", dns_rd_uint16(msg));
	    dumpdata(msg, "tkey.other", dns_rd_uint16(msg));
	    dns_rd_end(msg);
	} else {
	    len = dns_rd_data(msg, data, sizeof data);
	    if (len)
		dumphex(data, len);
	}
    }

    dns_msg_setbuf(msg, bufsave, bufszsave);
    fflush(stdout);
}
