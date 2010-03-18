/* (c) 2006, Quest Software Inc. All rights reserved */
/* David Leonard, 2006 */

#include "common.h"
#include "dns.h"
#include "dnsdebug.h"

extern int verbose;

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
static void dumpquestion(const struct dns_rr *question, const char *section);


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
    { 252, "AXFR" },
    { 253, "MAILB" },
    { 254, "MAILA" },
    { DNS_TYPE_ANY, "*" },
    {   0, 0 }
};

static struct desc rrclass_desc[] = {
    { DNS_CLASS_IN, "IN" },
    { 2, "CSNET" },
    { 3, "CHAOS" },
    { 4, "HESIOD" },
    { DNS_CLASS_NONE, "NONE" },
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
	fprintf(stderr, " %04x:", (int)i);
	for (j = i; j < i + 16; j++) {
	    if (j < len)
		fprintf(stderr, " %02x", data[j]);
	    else
		fprintf(stderr, "   ");
	    if (j == i + 7)
		putc(' ', stderr);
	}

	fprintf(stderr, "   ");
	for (j = i; j < i + 16 && j < len; j++) {
	    if (data[j] < ' ' || data[j] >= 0x7f)
		putc('.', stderr);
	    else
		putc(data[j], stderr);
	    if (j == i + 7)
		putc(' ', stderr);
	}
	putc('\n', stderr);
    }

}

static void
dumpdata(struct dns_msg *msg, const char *name, uint16_t len)
{
    unsigned char *p;
   
    p = (unsigned char *)msg->data + dns_msg_getpos(msg);
    dns_rd_skip(msg, len);
    fprintf(stderr, "\t%-20s: (len=%d)\n", name, len);
    dumphex(p, len);
}

static void
dumpname(struct dns_msg *msg, const char *name)
{
    char buf[DNS_MAXNAME];
    dns_rd_name(msg, buf, sizeof buf);
    fprintf(stderr, "\t%-20s: %s\n", name, buf);
}

static void
dumpuint16(struct dns_msg *msg, const char *name)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    fprintf(stderr, "\t%-20s: %u (0x%x)\n", name, v, v);
}

static void
dumpuint16desc(struct dns_msg *msg, const char *name, struct desc *desc)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    fprintf(stderr, "\t%-20s: %s (%u)\n", name, desc_lookup(desc, v), v);
}

static void
dumpuint16rcode(struct dns_msg *msg, const char *name)
{
    uint16_t v;
    v = dns_rd_uint16(msg);
    fprintf(stderr, "\t%-20s: %s\n", name, dns_rcode_name(v));
}

static void
dumpuint32(struct dns_msg *msg, const char *name)
{
    uint32_t v;
    v = dns_rd_uint32(msg);
    fprintf(stderr, "\t%-20s: %u (0x%x)\n", name, v, v);
}

static void
dumpuint32time(struct dns_msg *msg, const char *name)
{
    uint32_t v;
    time_t t;
    v = dns_rd_uint32(msg);
    t = (time_t)v;
    fprintf(stderr, "\t%-20s: %.24s (0x%x)\n", name, ctime(&t), v);
}

static void
dumpuint32rtime(struct dns_msg *msg, const char *name)
{
    static struct {
	const char *abbrev;
	uint32_t interval;
    } intervals[] = {
	{ "d", 24 * 60 * 60 },
	{ "h", 60 * 60 },
	{ "m", 60 },
	{ "s", 1 },
    };
    uint32_t v,t;
    int i, printed_something = 0;

    v = dns_rd_uint32(msg);
    t = v;
    fprintf(stderr, "\t%-20s:", name);
    for (i = 0; i < sizeof intervals / sizeof intervals[0]; i++) 
	if (t >= intervals[i].interval || printed_something) {
	    int x = t / intervals[i].interval;
	    if (t) {
		fprintf(stderr, " %d%s", x, intervals[i].abbrev);
		printed_something = 1;
	    }
	    t = t - x * intervals[i].interval;
	}
    if (!printed_something)
	fprintf(stderr, " 0");
    fprintf(stderr, " (0x%x)\n", v);
}

static void
dumpheader(const struct dns_header *hdr)
{
    fprintf(stderr, "    header:\n");
    fprintf(stderr, "\t%-20s: 0x%04x\n", "id", hdr->id);
    fprintf(stderr, "\t%-20s: %s\n", "response", hdr->response ? "RESPONSE" : "QUERY");
    fprintf(stderr, "\t%-20s: %s\n", "opcode", desc_lookup(opcode_desc, hdr->opcode));
    fprintf(stderr, "\t%-20s: %s\n", "authoritative", hdr->authoritative ? "yes" : "no");
    fprintf(stderr, "\t%-20s: %s\n", "truncated", hdr->truncated ? "yes" : "no");
    fprintf(stderr, "\t%-20s: %s\n", "recurse-desired", 
	    hdr->recurse_desired ? "yes" : "no");
    fprintf(stderr, "\t%-20s: %s\n", "recurse-avail", hdr->recurse_avail ? "yes" : "no");
    fprintf(stderr, "\t%-20s: %s (%u)\n", "rcode", 
	    dns_rcode_name(hdr->rcode), hdr->rcode);
    fprintf(stderr, "\t%-20s: %u\n", "qdcount", hdr->qdcount);
    fprintf(stderr, "\t%-20s: %u\n", "ancount", hdr->ancount);
    fprintf(stderr, "\t%-20s: %u\n", "nscount", hdr->nscount);
    fprintf(stderr, "\t%-20s: %u\n", "arcount", hdr->arcount);
}


static void
dumprr_part(const struct dns_rr *rr)
{
    fprintf(stderr, "\t%-20s: \"%s\"\n", "name", rr->name);
    fprintf(stderr, "\t%-20s: %s (%u)\n", "type", 
	    desc_lookup(rrtype_desc, rr->type), rr->type);

    fprintf(stderr, "\t%-20s: %s (%u)\n", "class", 
	    desc_lookup(rrclass_desc, rr->class_), rr->class_);

}

void
dumprr(const struct dns_rr *rr, const char *name)
{
    fprintf(stderr, "    %s:\n", name);
    dumprr_part(rr);
    fprintf(stderr, "\t%-20s: %ld sec\n", "ttl", (long)rr->ttl);
}

static void
dumpquestion(const struct dns_rr *question, const char *section)
{
    fprintf(stderr, "    %s:\n", section);
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
    const char *section_names_query[] = {
	"question", "answer", "authority", "additional" };
    const char *section_names_update[] = {
	"zone", "prerequisite", "update", "additional" };
    const char **section_names;
    const char *section_name;
    size_t savepos;
    void *bufsave;
    size_t bufszsave;

    fprintf(stderr, "-------\n");

    assert(dns_msg_getpos(msg) == 0);
    dns_msg_getbuf(msg, &bufsave, &bufszsave);
    if (verbose > 2)
	dumphex(bufsave, bufszsave);

    dns_rd_header(msg, &header);
    dumpheader(&header);
    section_names = header.opcode == DNS_OP_UPDATE 
	? section_names_update 
	: section_names_query;

    section_name = section_names[0];
    for (i = 0; i < header.qdcount; i++) {
	dns_rd_question(msg, &rr);
	dumpquestion(&rr, section_name);
    }

    for (;;) {
	if (header.ancount) { 
	    section_name = section_names[1];
	    header.ancount--; 
	} else if (header.nscount) {
	    section_name = section_names[2];
	    header.nscount--; 
	} else if (header.arcount) {
	    section_name = section_names[3];
	    header.arcount--;
	} else 
	    break;

	dns_rd_rr_head(msg, &rr);
	dumprr(&rr, section_name);

	/* Extract the rdata length without moving the read pointer */
	savepos = dns_msg_getpos(msg);
	dumpuint16(msg, "rdata.length");
	dns_rd_setpos(msg, savepos);

	if (rr.type == 250) {
	    uint16_t timehi;
	    uint32_t timelo;
	    time_t t;

	    dns_rd_begin(msg);
	    dumpname(msg, "tsig.algorithm");
	    timehi = dns_rd_uint16(msg);
	    timelo = dns_rd_uint32(msg);
	    /* Note: on 32-bit time_t systems, higher order bits are lost */
	    t = timehi << 32 | timelo;
	    fprintf(stderr, "\t%-20s: 0x%x:%08x (%.24s)\n", "tsig.time",
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
	} else if (rr.type == 6) {
	    dns_rd_begin(msg);
	    dumpname(msg, "soa.mname");
	    dumpname(msg, "soa.rname");
	    dumpuint32(msg, "soa.serial");
	    dumpuint32rtime(msg, "soa.refresh");
	    dumpuint32rtime(msg, "soa.retry");
	    dumpuint32rtime(msg, "soa.expire");
	    dumpuint32(msg, "soa.minttl");
	    dns_rd_end(msg);
	} else if (rr.type == 2) {
	    dns_rd_begin(msg);
	    dumpname(msg, "ns.nsdname");
	    dns_rd_end(msg);
	} else {
	    len = dns_rd_data(msg, data, sizeof data);
	    if (len)
		dumphex(data, len);
	}
    }

    len = msg->remain[msg->depth];
    if (len != 0) {
        fprintf(stderr, "    %s:\n", "(LEFTOVER)");
        dumphex((char *)msg->data + msg->pos, len);
    }

    dns_msg_setbuf(msg, bufsave, bufszsave);
    fflush(stdout);
}
