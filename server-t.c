/* (c) 2008, Quest Software Inc. All rights reserved. */
/*
 * A test DNS server.
 *
 * This tool is used to test DNS clients. 
 *
 * It has two modes: either DNS requests are received on stdin or a TCP port,
 * OR requests are received on a unix domain socket.
 *
 * The tool waits for DNS request messages, and matches them against request
 * pattern given on the command line. For each matched request, a response
 * is constructed from a subsequent pattern.
 *
 * This continues for successive pairs of arguments on the command line,
 * until none are left, in which case the tool waits for the client to close
 * the connection and then exits with a success code.
 *
 * The program exits with success only if all received requests match 
 * and there were no other errors sending the responses.
 *
 * In 'unix domain mode', the -u option specifies the process to run
 * as a child process with an environment variable set to a unix domain
 * socket. dnsupdate's TCP functions will see this environment and use
 * the domain socket wheneve it needs to connect to a nameserver. In
 * this way, all DNS traffic from dnsupdate can be wrapped and tested.
 *
 *
 * PATTERN EXAMPLE
 *
 * Here is a simple example of a arguments to service a single
 * IP address lookup for a given domain and the sending back of a valid 
 * response.
 *
 *    'Q:foo.example.com A' 'OK:foo.example.com A 1.2.3.4'
 *
 * When run in -u mode, the request can be prefixed with a host name in
 * square brackets:
 *
 *    '[127.0.0.1]Q:foo.example.com A' 'OK:foo.example.com A 1.2.3.4'
 *
 * REQUEST PATTERN
 *
 * Request pattern strings start with a header type (Q,I,S or U) followed by
 * optional constraints on flags (+a or -a for authoritative), then a colon
 * followed by the question record patterns.
 *
 * The question record patterns are a name followed by an optional type 
 * and a class:
 *
 *      name [type] class
 *
 * The name is a domain name, where the special name ? matches any name. 
 * If a name has to start with a number, prefix it with a quote (').
 * The type can be IN or ANY. If omitted, it is ignored.
 * The class can be one of A SOA NS CNAME or other various types.
 *
 * For the 2nd and subsequent sections, more data may be matched in the
 * pattern: the TTL and RDATA fields may be specified:
 *
 *      name [ttl] [type] class {rdata}
 *
 * The ttl is an integer in seconds. If omitted, it is ignored.
 * The rdata depends on the class and is used to match the request.
 * Omitted fields are ignored.
 *
 *		CNAME domain
 *		NS    domain
 *		PTR   domain
 *		SOA   domain domain int int int int int
 *		A     dotted-IPv4-address
 *
 * An empty rdata is expressed by '~'.
 *
 * Other record patterns suitable for use anywhere in a section are:
 *
 *      *       - matches any single resource
 *      **      - matches all remaining resources in the section
 *
 * Successive records in a section are delimited by commas. 
 * Sections are delimited by colons. 
 * If a section is omitted, it is not checked.
 *
 *
 *
 * RESPONSE PATTERN
 *
 * The response patterns begins with an rcode (usually 'OK' indicating
 * no error) optionally followed by flag modifiers (+a, -a etc).
 * Then, a colon introduces the answer records (the question records
 * are copied from the request packet).
 * Records are delimited by commas.
 * Sections are delimited by colons.
 *
 * Like the request pattern, records are of the form
 *
 *      name [ttl] [type] class {rdata}
 *
 * If the ttl is omitted it defaults to something sensible.
 * If the type is omitted it defaults to IN.
 * Depending on the class, omitted rdata fields default to sensible values.
 *
 */

#include "common.h"
#include "dns.h"
#include "dnstcp.h"
#include "dnsdebug.h"
#include "err.h"

#include <signal.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/poll.h>

#define TAG "server-t: "

static void del_fd(int fd);
static int  build_unix_listener(void);
static void start_child(char **argv);
static int  poll_fds(void);
static int  stop_child(void);
static void kill_child(void);

static int child_exited;
static pid_t child_pid;
int verbose = 0;
static int opt_notimeout;   /* -N */

/* Tables */
static struct lookup {
    const char *name;
    int value;
} /*lookup_opcode[] = {
    { "QUERY", DNS_OP_QUERY },
    { "IQUERY", DNS_OP_IQUERY },
    { "STATUS", DNS_OP_STATUS },
    { "UPDATE", DNS_OP_UPDATE },
    { 0 }
},*/ lookup_rcode[] = {
    { "NOERROR", DNS_NOERROR },
    { "FORMERR", DNS_FORMERR },
    { "SERVFAIL", DNS_SERVFAIL },
    { "NXDOMAIN", DNS_NXDOMAIN },
    { "NOTIMP", DNS_NOTIMP },
    { "REFUSED", DNS_REFUSED },
    { "YXDOMAIN", DNS_YXDOMAIN },
    { "YXRRSET", DNS_YXRRSET },
    { "NXRRSET", DNS_NXRRSET },
    { "NOTAUTH", DNS_NOTAUTH },
    { "NOTZONE", DNS_NOTZONE },
    { "BADSIG", DNS_BADSIG },
    { "BADKEY", DNS_BADKEY },
    { "BADTIME", DNS_BADTIME },
    { "BADMODE", DNS_BADMODE },
    { "BADNAME", DNS_BADNAME },
    { "BADALG", DNS_BADALG },
    { 0 }
}, lookup_type[] = {
    { "A", DNS_TYPE_A },
    { "NS", DNS_TYPE_NS },
    { "CNAME", DNS_TYPE_CNAME },
    { "SOA", DNS_TYPE_SOA },
    { "NULL", DNS_TYPE_NULL },
    { "PTR", DNS_TYPE_PTR },
    { "TXT", DNS_TYPE_TXT },
    { "TKEY", DNS_TYPE_TKEY },
    { "TSIG", DNS_TYPE_TSIG },
    { "ANY", DNS_TYPE_ANY },
    { 0 }
}, lookup_class[] = {
    { "IN", DNS_CLASS_IN },
    { "NONE", DNS_CLASS_NONE },
    { "ANY", DNS_CLASS_ANY },
    { 0 }
};

/* Returns true if the string bound by start,end is the same as the string */
static int
streq(const char *str, const char *end, const char *match)
{
    while (str < end)
	if (*str++ != *match++)
	    return 0;
    return *match == '\0';
}

/* Look up a string in the table above. Numeric strings are converted to int. */
static int
lookup(const char *start, const char *end, struct lookup *table)
{
    const char *s;
    int i;

    if (start < end && *start >= '0' && *start <= '9') {
	i = 0;
	for (s = start; s < end; s++)
	    if (*s >= '0' && *s <= '9')
		i = i * 10 + (*s - '0');
	    else
		return -1;
	return i;
    }

    for (i = 0; table[i].name; i++)
	if (streq(start, end, table[i].name))
	    return table[i].value;
    return -1;
}

/* Returns a string for a number that would match in a table with lookup() */
static const char *
unlookup(int value, struct lookup *table)
{
    int i;
    static char numeric[16];

    for (i = 0; table[i].name; i++)
	if (table[i].value == value)
	    return table[i].name;
    snprintf(numeric, sizeof numeric, "%d", value);
    return numeric;
}

/*
 * Fills response message (rmsg) with a reply built from 
 * the query message (qmsg) and the pattern.
 * Reads the header and question records from qmsg.
 */
static void
wr_response(struct dns_msg *rmsg, struct dns_msg *qmsg, const char *pattern)
{
    struct dns_header header;
    const char *p;
    struct dns_rr rr;
    int section, i;
    const char *start;
    uint16_t mark;
    uint32_t u32;

    if (verbose > 2)
	fprintf(stderr, TAG"wr_response '%s'\n", pattern);

    /* Read the header from the query to become the reply header */
    dns_rd_header(qmsg, &header);

    /* Always set the response bit */
    header.response = 1;

    /* Read the rcode from the beginning of the pattern */
    p = pattern;
    while (*p && *p != ':' && *p != '+' && *p != '-')
	p++;
    if (p != pattern)
	header.rcode = DNS_NOERROR;
    else
	header.rcode = lookup(pattern, p, lookup_rcode);

    if (verbose > 2) {
	fprintf(stderr, TAG"  header.opcode %u\n", header.opcode);
	fprintf(stderr, TAG"  header.rcode %u\n", header.rcode);
    }

    /* Modify the reply header according to flag modifiers ({-+}{a})*[:...] */
    while (*p && *p != ':') {
	int bit;
	if (*p != '-' && *p != '+')
	    errx(1, "expected - or + before header flag (%s)", pattern);
	bit = (*p++ == '+');
	switch (*p) {
	case 'a':
	    header.authoritative = bit;
	    break;
	default:
	    errx(1, "unknown header flag (%s)", pattern);
	}
	if (*p) p++;
    }

    /* Zero counts and write the header. Counts will be incremented later */
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    dns_wr_header(rmsg, &header);

    /* Copy and write the questions from the query without change. */
    for (i = 0; i < header.qdcount; i++) {
	dns_rd_question(qmsg, &rr);
	dns_wr_question(rmsg, &rr);
    }

    section = 0;
    while (*p) {
	/* If this pattern starts with ':' then it is a new section,
	 * otherwise ',' indicates a continued section */
	switch (*p) {
	case ':': section++; break;
	case ',': break;
	default: errx(1, "unexpected character %c", *p);
	}
	p++;

	if (*p == ':' || !*p)	/* empty section */
	    continue;

	if (verbose > 2)
	    fprintf(stderr, TAG"   section %d\n", section);

	/* Convenience macros. Yucky, but "testing-quality". */
/* skip over spaces */
#define SKIPSPACE(p) while (*p == ' ' || *p == '\t') p++
/* skip over numbers */
#define SKIPNUMBER(p) while (*p >= '0' && *p <= '9') p++
/* skip over a non-whitespace word, not including ':' or ',' */
#define SKIPWORD(p)  while (*p && *p != ',' && *p != ' ' && \
			    *p != '\t' && *p != ':') p++
/* Read and skip a domain name into a char buffer. Nul terminate it */
#define SKIPNAME(p, name) do { \
	if (*p == '\'') p++; \
	start = p; \
	SKIPWORD(p); \
	if (p - start > sizeof name + 1) \
	    errx(1, "name too long: %.*s", p - start, p); \
	memcpy(name, start, p - start); \
	name[p - start] = '\0'; \
    } while (0)
/* Read and skip an integer in base 10 */
#define SKIPI32(p, i) do { \
	start = p; \
	i = 0; \
	while (*p >= '0' && *p <= '9') \
	    i = i * 10 + (*p++ - '0'); \
	if (start == p) \
	    errx(1, "bad integer at '%s'", start); \
    } while (0)
/* Read and skip an integer in base 10, or default to a value */
#define SKIPI32D(p, i, dfl) do { \
	if (*p >= '0' && *p <= '9') \
	    SKIPI32(p, i); \
	else \
	    i = dfl; \
    } while (0)

	/* Read the resource name */
	SKIPSPACE(p);
	SKIPNAME(p, rr.name);

	if (verbose > 2)
	    fprintf(stderr, TAG"     rr.name '%s'\n", rr.name);

	/* Look for a TTL integer */
	SKIPSPACE(p);
	start = p; SKIPNUMBER(p);
	if (p == start)
	    rr.ttl = 1800;  /* default ttl */
	else {
	    rr.ttl = lookup(start, p, NULL);
	    SKIPSPACE(p);
	}
	if (verbose > 2)
	    fprintf(stderr, TAG"     rr.ttl %u\n", rr.ttl);

	/* Read the next symbol which is either a class or a type */
	start = p; SKIPWORD(p);
	i = lookup(start, p, lookup_class);
	if (i == -1)
	    rr.class_ = DNS_CLASS_IN;
	else {
	    /* It was recognised as a class, so read the next symbol */
	    rr.class_ = i;
	    SKIPSPACE(p);
	    start = p; SKIPWORD(p);
	}
	if (verbose > 2)
	    fprintf(stderr, TAG"     rr.class_ %u\n", rr.class_);

	/* Look up the symbol as a type */
	i = lookup(start, p, lookup_type);
	if (i == -1)
	    errx(1, "unknown type '%.*s'", p-start, start);
	rr.type = i;
	if (verbose > 2)
	    fprintf(stderr, TAG"     rr.type %u\n", rr.type);
	SKIPSPACE(p);

	/* We have a full record header now, so write it and begin
	 * the data portion */
	dns_wr_rr_head(rmsg, &rr);
	dns_wr_begin(rmsg, &mark);

	if (*p == '~')
	    p++;	    /* ~ indicates an empty rdata */
	else
	  /* Write the RDATA part of the resource depending on the type */
	  switch (rr.type) {
	  case DNS_TYPE_A: {
	    /* IPv4 address */
	    unsigned char addr[4];
	    uint32_t n;
	    if (verbose > 3)
		fprintf(stderr, TAG"     writing IPv4 address for A class\n");
	    for (i = 0; i < 4; i++) {
		if (i && *p++ != '.') errx(1, "bad IP address");
		SKIPI32(p, n);
		if (n > 255) errx(1, "bad IP address");
		addr[i] = n;
	    }
	    dns_wr_data_raw(rmsg, addr, sizeof addr);
          } break;
	  case DNS_TYPE_NS:
	  case DNS_TYPE_PTR:
	  case DNS_TYPE_CNAME:
	    /* Resources consisting of a single domain name */
	    SKIPNAME(p, rr.name); dns_wr_name(rmsg, rr.name);
	    break;
	  case DNS_TYPE_SOA:
	    /* Start of authority record. Default a whole bunch */
	    SKIPNAME(p, rr.name); dns_wr_name(rmsg, rr.name);	/* MNAME */
	    SKIPSPACE(p);
	    SKIPNAME(p, rr.name); dns_wr_name(rmsg, rr.name);	/* RNAME */
	    SKIPSPACE(p);
	    SKIPI32(p, u32); dns_wr_uint32(rmsg, u32);		/* SERIAL */
	    SKIPSPACE(p);
	    SKIPI32D(p, u32, 3600); dns_wr_uint32(rmsg, u32);	/* REFRESH */
	    SKIPSPACE(p);
	    SKIPI32D(p, u32, 3600); dns_wr_uint32(rmsg, u32);	/* RETRY */
	    SKIPSPACE(p);
	    SKIPI32D(p, u32, 3600); dns_wr_uint32(rmsg, u32);	/* EXPIRE */
	    SKIPSPACE(p);
	    SKIPI32D(p, u32, 3600); dns_wr_uint32(rmsg, u32);	/* MINIMUM */
	    break;
	  default:
	    errx(1, "Unknown resource type %d", rr.type);
	  }

	dns_wr_end(rmsg, &mark);

	/* Increment the right section counter */
	switch (section) {
	case 1: dns_wr_inc_ancount(rmsg); break;
	case 2: dns_wr_inc_nscount(rmsg); break;
	case 3: dns_wr_inc_arcount(rmsg); break;
	default: errx(1, "too many sections");
	}
    }
}

/*
 * Reads a DNS query message and returns false if it doesn't match.
 */
int
match_query(struct dns_msg *qmsg, const char *pattern)
{
    struct dns_header header;
    struct dns_rr rr, rm;
    const char *p, *patstart, *patend, *start;
    int section;
    int records_left;
    int recno;
    int i;
    static const char *section_name[] = 
	{ "?", "question", "answer", "authoritative", "additional", "?" };

    if (verbose > 2)
	fprintf(stderr, TAG"match_query pattern '%s'\n", pattern);

    dns_rd_header(qmsg, &header);

    /* If the message is a reponse, then fail immediately. 
     * We want a 'query' packet */
    if (header.response) {
	fprintf(stderr, TAG"header match failed: response!\n");
	return 0;
    }

    /* First character of pattern is the expected query type */
    p = pattern;
    switch (*p) {
    case 'Q': if (header.opcode != DNS_OP_QUERY) return 0; break;
    case 'I': if (header.opcode != DNS_OP_IQUERY) return 0; break;
    case 'S': if (header.opcode != DNS_OP_STATUS) return 0; break;
    case 'U': if (header.opcode != DNS_OP_UPDATE) return 0; break;
    default: errx(1, "unknown query code '%c'", *p);
    }
    p++;

    /* Successive patterns are flag requirements */
    while (*p && *p != ':') {
	unsigned int actual, expected;
	if (*p != '-' && *p != '+')
	    errx(1, "expected + or - for flag");
	expected = (*p == '+');
	switch (*++p) {
	case 'a': actual = header.authoritative; break;
	default: errx(1, "unknown flag %c", *p);
	}
	if (verbose > 2)
	    fprintf(stderr, TAG"  testing header flag %c == %u\n", *p, expected);
	if (actual != expected) {
	    fprintf(stderr, TAG"flag %c%c match failed\n",
		    expected ? '+' : '-', *p);
	    return 0;
	}
	p++;
    }

    section = 0;
    records_left = 0;
    SKIPSPACE(p);
    while (*p) {
	switch (*p) {
	case ':': 
	    recno = 0;
	    if (records_left) {
		fprintf(stderr, TAG"unmatched records in %s section\n",
		   section_name[section]);
		return 0;
	    }
	    section++;
	    records_left = 
		   section == 1 ? header.qdcount :
		   section == 2 ? header.ancount :
		   section == 3 ? header.nscount :
		   section == 4 ? header.arcount : -1;
	    SKIPSPACE(p);
	    break;
	case ',':
	    recno++;
	    SKIPSPACE(p);
	    break;
	default:
	    errx(1, "unexpected pattern char 0x%02x '%c'", *p, *p);
	}
	p++;
	if (*p == ':')
	    continue;

	if (verbose > 2)
	    fprintf(stderr, TAG"  section %d (records_left %d)\n", section, records_left);

	/* Handle the '**' pattern which consumes the remaining records */
	if (*p == '*' && *(p+1) == '*') {
	    /* Just skip the rest of the records in this section */
	    while (records_left) {
		if (section == 1)
		    dns_rd_question(qmsg, &rr);		
		else {
		    dns_rd_rr_head(qmsg, &rr);		
		    dns_rd_skip(qmsg, dns_rd_uint16(qmsg));
		}
		records_left--;
	    }
	    p += 2;
	    continue;
	}

	patend = patstart = p;
	while (*patend && *patend != ',' && *patend != ':') patend++;

	if (verbose > 2)
	    fprintf(stderr, TAG"  pattern '%.*s'\n", (int)(patend - patstart), patstart);

	/* Check that there are records left to match */
	if (!records_left--) {
	    fprintf(stderr, TAG"%.*s: not enough records in %s section\n",
		    (int)(patend - patstart), patstart, 
		    section_name[section]);
	    return 0;
	}

	/* Read the resource into rr */
	if (section == 1)
	    dns_rd_question(qmsg, &rr);
	else
	    dns_rd_rr_head(qmsg, &rr);		

	/* '*' matches any resource */
	if (*p == '*') {
	    if (verbose > 2)
		fprintf(stderr, TAG"    '*' matches any resource\n");
	    if (section > 1)
		dns_rd_skip(qmsg, dns_rd_uint16(qmsg));
	    p++;
	    continue;
	}

	/* Read the name from the query */
	SKIPSPACE(p);
	SKIPNAME(p, rm.name);
	SKIPSPACE(p);
	if (strcmp(rm.name, "?") == 0) {
	    if (verbose > 2)
		fprintf(stderr, TAG"    '?' matches name '%s'\n", rm.name);
	} else if (strcasecmp(rr.name, rm.name) == 0) {
	    if (verbose > 2)
		fprintf(stderr, TAG"    pattern matches name '%s'\n", rm.name);
	} else {
	    fprintf(stderr, TAG"'%.*s': name mismatch: %s %s (%s:%d)\n",
		    (int)(patend - patstart), patstart, rm.name, rr.name,
		    section_name[section], recno);
	    return 0;
	}

	if (section > 1) {
	    /* Look for a TTL integer */
	    SKIPSPACE(p);
	    start = p; SKIPNUMBER(p);
	    if (p != start) {
		rm.ttl = lookup(start, p, NULL);
		if (verbose > 2)
		    fprintf(stderr, TAG"    matching ttl %u\n", rm.ttl);
		if (rm.ttl != rr.ttl) {
		    fprintf(stderr, TAG"'%.*s': ttl mismatch: %d (%s:%d)\n",
			    (int)(patend - patstart), patstart, rr.ttl,
			    section_name[section], recno);
		    return 0;
		}
	    }
	}

	/* Read the next symbol which is either a class or a type */
	SKIPSPACE(p);
	start = p; SKIPWORD(p);
	i = lookup(start, p, lookup_class);
	if (i == -1) {
	    if (verbose > 2)
		fprintf(stderr, TAG"  no class in pattern; actual %s\n",
			unlookup(rr.class_, lookup_class));
	} else {
	    rm.class_ = i;
	    if (verbose > 2)
		fprintf(stderr, TAG
			"  matching pattern class %s against actual %s\n",
			unlookup(rm.class_, lookup_class),
			unlookup(rr.class_, lookup_class));
	    if (rm.class_ != rr.class_) {
		fprintf(stderr, TAG"%.*s: class mismatch: %s (%s:%d)\n",
			(int)(patend - patstart), patstart, 
			unlookup(rr.class_, lookup_class),
			section_name[section], recno);
		return 0;
	    }
	    /* It was recognised as a class, so read the next symbol */
	    SKIPSPACE(p);
	    start = p; SKIPWORD(p);
	}
	/* Look up the symbol as a type */
	i = lookup(start, p, lookup_type);
	if (i == -1)
	    errx(1, "unknown type '%.*s'", p-start, start);
	rm.type = i;
	SKIPSPACE(p);

	if (verbose > 2)
	    fprintf(stderr, TAG"  matching pattern type %s against actual %s\n",
		    unlookup(rm.type, lookup_type),
		    unlookup(rr.type, lookup_type));
	if (rm.type != rr.type) {
	    fprintf(stderr, TAG"%.*s: type mismatch: %s (%s:%d)\n",
		    (int)(patend - patstart), patstart, 
		    unlookup(rr.type, lookup_type),
		    section_name[section], recno);
	    return 0;
	}

	/* Question sections cannot have data */
	if (section == 1) {
	   if (p != patend)
	       errx(1, "unexpected data after question pattern: %.*s",
		       (int)(patend - patstart), patstart);
	   continue;
	}

	dns_rd_begin(qmsg);
	if (*p == '~') {
	    if (verbose > 2)
		fprintf(stderr, TAG"matching empty rdata (~)\n");
	    p++;    /* Expect an empty rdata */
	} else
	    switch (rm.type) {
	    case DNS_TYPE_A: {
		/* IPv4 address */
		unsigned char maddr[4];
		unsigned char raddr[4];
		uint32_t n;
		assert(sizeof raddr == 4);
		if (dns_rd_remain(qmsg) != 4) {
		    fprintf(stderr, TAG"bad A record size %d (%s:%d)\n",
			    dns_rd_remain(qmsg),
			    section_name[section], recno);
		    return 0;
		}
		dns_rd_data_raw(qmsg, raddr, sizeof raddr);
		if (*p == '?') {	    /* ? matches any address */
		    p++;
		    break;
		}
		for (i = 0; i < 4; i++) {
		    if (i && *p++ != '.') errx(1, "bad IP address");
		    SKIPI32(p, n);
		    if (n > 255) errx(1, "bad IP address");
		    maddr[i] = n;
		}
		if (memcmp(raddr, maddr, sizeof raddr) != 0) {
		   fprintf(stderr, TAG
			   "%.*s: A address mismatch: %d.%d.%d.%d (%s:%d)\n",
			    (int)(patend - patstart), patstart, 
			    raddr[0], raddr[1], raddr[2], raddr[3],
			    section_name[section], recno);
		   return 0;
		}
	    } break;
	    
	    case DNS_TYPE_NS:
	    case DNS_TYPE_PTR:
	    case DNS_TYPE_CNAME:
		dns_rd_name(qmsg, rr.name, sizeof rr.name);
		SKIPNAME(p, rm.name);
		SKIPSPACE(p);
		if (!rm.name[0])
		    errx(1, "%.*s: require name or '?' after type",
			    (int)(patend - patstart), patstart);
		if (strcmp(rm.name, "?") != 0 && strcasecmp(rr.name, rm.name) != 0){
		    fprintf(stderr, TAG"%.*s: value mismatch: %s (%s:%d)\n",
			    (int)(patend - patstart), patstart, rr.name,
			    section_name[section], recno);
		    return 0;
		}
		break;

	    default:
		/* Always skip unhandled record types whan '*' is provided */
		if (*p != '*')
		    errx(1, "unhandled pattern type requires '*'");
		p++;
		dns_rd_skip(qmsg, dns_rd_remain(qmsg));
		break;
	    }

	if (dns_rd_remain(qmsg)) {
	    fprintf(stderr, TAG"unexpected %d bytes remaining (%s:%d)\n",
		dns_rd_remain(qmsg),
		section_name[section], recno);
	    return 0;
	}
	dns_rd_end(qmsg);
	SKIPSPACE(p);
    }
    return 1;
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Waits and accepts a single connection on the given port */
int
tcp_accept(int port)
{
    int s, t;
    struct sockaddr_in addr;
    struct sockaddr saddr;
    socklen_t saddrlen;

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	err(1, "socket");
#ifdef SO_REUSEADDR
    { int on = 1;
      if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) < 0)
	  warn("setsockopt SO_REUSEADDR"); }
#endif
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0)
	err(1, "bind");
    if (listen(s, 1) < 0)
	err(1, "listen");
    if (verbose)
	fprintf(stderr, TAG"accepting on port %d\n", port);
    saddrlen = sizeof saddr;
    if ((t = accept(s, &saddr, &saddrlen)) < 0)
	err(1, "accept");
    if (verbose > 2)
	fprintf(stderr, TAG"  accepted connection\n");
    if (close(s) < 0)
	warn("close s");
    if (verbose > 2)
	fprintf(stderr, TAG"  returning socket %d\n", t);
    return t;
}

/* Reads socket, expecting a close (and no data) */
void
tcp_wait_close(int fd)
{
    char data[1];
    int len;

    /* Read, expecting a length of 0 (i.e client closes connection) */
    len = read(fd, data, 1);
    if (len < 0)
	err(1, "read");
    if (len > 0) {
	fprintf(stderr, TAG"unexpected message recieved from client!\n");
	exit(1);
    }
    if (close(fd) < 0)
	err(1, "close");
}

static char **handled_patterns;

static void
handle_msg(char *host, char *msgbuf, int msglen, int fd)
{
    char outbuf[65535];
    struct dns_msg inmsg;
    struct dns_msg outmsg;
    char *request, *response;
    char *request_host = NULL;

    dns_msg_setbuf(&inmsg, msgbuf, msglen);

    if (!*handled_patterns) {
	fprintf(stderr, TAG "unexpected message received");
	if (host) fprintf(stderr, " for host '%s'", host);
	fprintf(stderr, " follows:\n");
	dumpmsg(&inmsg);
	exit(1);
    }

    if (verbose)
	dumpmsg(&inmsg);

    request = *handled_patterns++;
    response = *handled_patterns++;
    if (verbose > 3) {
	fprintf(stderr, TAG"request = %s\n", request);
	fprintf(stderr, TAG"response = %s\n", response);
    }

    if (*request == '[') {
	if (!host)
	    errx(1, "patterns starting with '[host]' only valid with -u");
	request_host = ++request;
	while (*request && *request != ']')
	    request++;
	if (*request == ']')
	    *request++ = '\0';
	if (strcasecmp(host, request_host) != 0) {
	    fprintf(stderr, TAG
		    "request for host '%s' failed to match pattern '[%s]%s'\n",
		    host, request_host, request);
	    exit(1);
	}
    }

    if (!match_query(&inmsg, request)) {
	fprintf(stderr, TAG"request failed to match '%s'\n", request);
	fprintf(stderr, TAG"request received%s%s follows:\n",
		host ? " for " : "", host ? host : "");
	dns_msg_setbuf(&inmsg, msgbuf, msglen);
	dumpmsg(&inmsg);
	exit(1);
    }
    if (verbose)
	fprintf(stderr, TAG"request:  '%s'\n", request);
    /* Rewind the input message */
    dns_msg_setbuf(&inmsg, msgbuf, msglen);
    /* Build the output message */
    dns_msg_setbuf(&outmsg, outbuf, sizeof outbuf);
    wr_response(&outmsg, &inmsg, response);
    if (verbose)
	fprintf(stderr, TAG"response: '%s'\n", response);
    dns_wr_finish(&outmsg);
    if (verbose)
	dumpmsg(&outmsg);
    /* Send the output message */
    if (dnstcp_sendmsg(fd, &outmsg) < 0)
	exit(1);
}

static RETSIGTYPE
sigint()
{
    fprintf(stderr, TAG"interrupted (cleaning up)\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    char inbuf[65535];
    int inlen;
    extern char *optarg;
    extern int optind;
    int ch;
    int error = 0;
    int port = -1;
    int fd;
    char **u_argv = NULL;

    while ((ch = getopt(argc, argv, "Np:u:v")) != -1)
	switch (ch) {
	case 'N':
	    opt_notimeout = 1;
	    break;
	case 'p':
	    port = atoi(optarg);
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'u':
	    optind--;
	    u_argv = argv + optind;
	    for (; optind < argc; optind++)
		if (strcmp(argv[optind], ";") == 0)
		    break;
	    if (optind == argc) {
		warnx("missing ';' argument after -u");
		error = 1;
	    } else
		argv[optind++] = NULL;
	    break;
	default:
	    error = 1;
	}

    if (optind == argc || (argc - optind) % 2 != 0) {
	warnx("missing or unmatched query/response arguments");
	error = 1;
    }
    if (port != -1 && u_argv) {
	warnx("-p and -u options are incompatible");
	error = 1;
    }
    if (error) {
	fprintf(stderr, "usage: %s [-p port | -u command ';'] query response ...\n", argv[0]);
	exit(1);
    }

    handled_patterns = argv + optind;

    if (u_argv == NULL) {
	/* Use either stdin as a socket, or wait for a port connection */
	if (port == -1)
	    fd = STDIN_FILENO;
	else
	    fd = tcp_accept(port);

	/* Read a query */
	while (*handled_patterns) {
	    if (verbose > 2)
		fprintf(stderr, TAG"receiving message\n");
	    inlen = dnstcp_recv(fd, inbuf, sizeof inbuf);
	    if (inlen < 0)
		exit(1);
	    if (verbose > 2)
		fprintf(stderr, TAG"  received message len %d\n", inlen);
	    handle_msg(NULL, inbuf, inlen, fd);
	}

	tcp_wait_close(fd);
    } else {
	if (signal(SIGINT, sigint) == SIG_ERR)
	    warn("signal SIGINT");
	fd = build_unix_listener();
	start_child(u_argv);
	while (poll_fds() && !child_exited) 
	    ;
	if (!child_exited) {
	    if (opt_notimeout)
		pause();
	    else
		sleep(2);
	    if (!child_exited)
		warnx("child did not exit after 2 seconds");
	}
	if (child_exited) {
	    if (!stop_child())
		errx(1, "child exited abnormally");
	    if (*handled_patterns)
		errx(1, "child exited, but patterns remain");
	} 
    }

    exit(0);
}

#define MAXFDS 5
static struct fdtab {
    int fd;
    void (*ready)(int fd, void *context);
    void *context;
} fdtab[MAXFDS];
static int nfdtab = 0;

/* Adds a file descriptor to be watched by poll_fds() */
static void
add_fd(int fd, void (*ready)(int fd, void *context), void *context)
{
    int i;
    struct fdtab *f = NULL;

    /* Use slots previously freed by del_fd() */
    for (i = 0; i < nfdtab; i++)
	if (fdtab[i].fd == -1) {
	    f = &fdtab[i];
	    break;
	}
    if (!f) {
	if (nfdtab >= MAXFDS)
	    errx(1, "add_fd: too many connections");
	f = &fdtab[nfdtab++];
    }
    f->fd = fd;
    f->ready = ready;
    f->context = context;
}

/* Removes an fd added by add_fd() */
static void
del_fd(int fd)
{
    int i;

    for (i = 0; i < nfdtab; i++)
	if (fdtab[i].fd == fd)
	    fdtab[i].fd = -1;
}


/* Polls the FDs added by add_fd() and calls their ready() fns.
 * Returns 1 if something may happen in the future */
static int
poll_fds()
{
    struct pollfd pfd[MAXFDS];
    struct fdtab *f;
    int i, nfds, ret;

    /* Initialise the poll array */
    nfds = 0;
    for (i = 0; i < nfdtab; i++) {
	if (fdtab[i].fd == -1) 
	    continue;
	pfd[nfds].fd = fdtab[i].fd;
	pfd[nfds].events = POLLIN;
	pfd[nfds].revents = 0;
	nfds++;
    }
    if (!nfds)
	return 0;
    if ((ret = poll(pfd, nfds, opt_notimeout ? -1 : 2000)) < 0) {
	if (errno != EINTR)
	    err(1, "poll");
	return -1;  /* Interrupt */
    }
    if (ret == 0)
	errx(1, "poll timed out after 2 seconds");
    for (i = 0; i < nfds; i++) {
	if ((pfd[i].revents & POLLIN) == 0)
	    continue;
	/* Scan the fdtab each time because a ready handler
	 * may modify the fdtab */
	for (f = fdtab; f < &fdtab[nfdtab]; f++)
	    if (f->fd == pfd[i].fd) {
		(*f->ready)(f->fd, f->context);
		f = NULL;
		break;
	    }
	assert(f == NULL);
	break;
    }
    return 1;
}

/* Record of an active DNS connection */
struct conn {
    enum { CONN_HOSTLEN, CONN_HOST, CONN_MSGLEN, CONN_MSG } state;
    int rlen;
    char lenbuf[2];
    uint16_t hostlen;
    char host[1024];
    uint16_t msglen;
    char msgbuf[65535];
};

/* Releases resources attached to a conn */
static void
del_conn(int fd, struct conn *conn)
{
    close(fd);
    del_fd(fd);
    free(conn);
}

/* Called when data is available for read on a conn */
static void
conn_ready(int fd, void *context)
{
    struct conn *conn = (struct conn *)context;
    int len;
    char *dest;
    int destsz;

    /* Each state has a destination for the data read */
    switch (conn->state) {
    case CONN_HOSTLEN:
    case CONN_MSGLEN:
	dest = conn->lenbuf;
	destsz = sizeof conn->lenbuf;
	break;
    case CONN_HOST:
	dest = conn->host;
	destsz = conn->hostlen;
	break;
    case CONN_MSG:
	dest = conn->msgbuf;
	destsz = conn->msglen;
	break;
    default:
	assert(!"bad conn->state");
    }

    /* Read partial data into dest, updating state->rlen */
    if (conn->rlen < destsz) {
	len = read(fd, dest + conn->rlen, destsz - conn->rlen);
	if (verbose > 3)
	    fprintf(stderr, TAG
		    "read %d of %d bytes from fd %d in state %s\n",
		    len, destsz - conn->rlen, fd, 
		    conn->state == CONN_HOSTLEN ? "CONN_HOSTLEN" :
		    conn->state == CONN_HOST    ? "CONN_HOST" :
		    conn->state == CONN_MSGLEN  ? "CONN_MSGLEN"  :
		    conn->state == CONN_MSG     ? "CONN_MSG"  :
		                                  "?bad");
	if (len <= 0) {
	    if (len < 0) 
		warn("read");
	    else if (conn->state == CONN_MSGLEN && conn->rlen == 0) {
		if (verbose)
		    fprintf(stderr, TAG"read clean EOF; closing connection\n");
	    } else
       		warnx("unexpected eof");
	    del_conn(fd, conn);
	    return;
	}
	conn->rlen += len;
    }

    /* When a destination is full, transit between states */
    if (conn->rlen == destsz) {
	switch (conn->state) {
	case CONN_HOSTLEN:
	    conn->hostlen = dest[0] << 8 | dest[1];
	    if (conn->hostlen >= sizeof conn->host) {
		warnx("host len too long %04x", conn->hostlen);
		del_conn(fd, conn);
		return;
	    }
	    conn->state = CONN_HOST;
	    break;
	case CONN_HOST:
	    conn->host[conn->hostlen] = '\0';
	    if (verbose)
		fprintf(stderr, "connection for %s\n", conn->host);
	    conn->state = CONN_MSGLEN;
	    break;
	case CONN_MSGLEN:
	    conn->msglen = dest[0] << 8 | dest[1];
	    conn->state = CONN_MSG;
	    break;
	case CONN_MSG:
	    handle_msg(conn->host, conn->msgbuf, conn->msglen, fd);
	    conn->state = CONN_MSGLEN;
	    break;
	default:
	    assert(!"bad conn->state");
	}
	conn->rlen = 0;
    }
}

/* Called when something connects to the unix listener socket. Builds a conn */
static void
unix_listener_ready(int fd, void *context)
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof addr;
    int t;
    struct conn *conn;

    if (verbose > 2)
	fprintf(stderr, TAG"accepting new connection\n");
    if ((t = accept(fd, &addr, &addrlen)) < 0) {
	warn("accept");
	return;
    }

    conn = (struct conn *)malloc(sizeof *conn);
    if (!conn)
	errx(1, "malloc");
    conn->state = CONN_HOSTLEN;
    conn->rlen = 0;
    add_fd(t, conn_ready, conn);
}

static char unix_listener_path[TMP_MAX];
static void
delete_unix_listener()
{
    if (verbose)
	fprintf(stderr, TAG"deleting %s\n", unix_listener_path);
    if (unlink(unix_listener_path) < 0)
	warn("unlink %s", unix_listener_path);
}

/* Creates the unix socket, setenvs DNSTCP_CONNECT_INTERCEPT, adds fd */
static int
build_unix_listener()
{
    int s;
    struct sockaddr_un sun;
    char *path;
    char *env;
    const char *envname = "DNSTCP_CONNECT_INTERCEPT";

    if (!(path = tmpnam(unix_listener_path)))
	errx(1, "tmpnam");
    assert(path == unix_listener_path);

    if (!(env = malloc(strlen(envname) + 1 + 5 + strlen(path) + 1)))
	errx(1, "malloc");
    sprintf(env, "%s=unix:%s", envname, path);
    if (putenv(env))
	err(1, "putenv");

    memset(&sun, 0, sizeof sun);
    snprintf(sun.sun_path, sizeof sun.sun_path, "%s", path);
    sun.sun_family = AF_UNIX;
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	err(1, "socket");
    if (bind(s, (struct sockaddr *)&sun, sizeof sun) < 0)
	err(1, "bind %s", path);
    atexit(delete_unix_listener);
    if (listen(s, 2) < 0)
	err(1, "listen");
    add_fd(s, unix_listener_ready, 0);
    return s;
}

static RETSIGTYPE
sigchld()
{
    child_exited = 1;
}

static void
kill_child()
{
    if (child_pid != -1) {
	if (verbose)
	    fprintf(stderr, TAG"sending kill signal to pid %d\n", child_pid);
	if (kill(child_pid, SIGKILL) < 0)
	    err(1, "kill %d", child_pid);
	stop_child();
    }
}

static void
start_child(char **argv)
{
    int i;

    if (verbose) {
	fprintf(stderr, TAG"start_child:");
	for (i = 0; argv[i]; i++)
	    fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
    }

    if (signal(SIGCHLD, sigchld) == SIG_ERR)
	err(1, "signal SIGCHLD");
    if ((child_pid = fork()) < 0)
	err(1, "fork");
    if (child_pid != 0) {
	if (verbose > 1)
	    fprintf(stderr, TAG"forked child pid %d\n", child_pid);
	atexit(kill_child);
	return;
    }

    execvp(argv[0], argv);
    warn("execvp %s", argv[0]);
    _exit(1);
}

/* Stop the child and return true if it exited with success */
static int
stop_child()
{
    int status;
    int ok;

    if (verbose > 1)
	fprintf(stderr, TAG"waiting for exit code from pid %d\n", child_pid);
    if (waitpid(child_pid, &status, 0) < 0)
	err(1, "waitpid %d", child_pid);
    child_pid = -1;
    ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (verbose || !ok) {
	if (WIFEXITED(status))
	   fprintf(stderr, TAG"child exit %d\n", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
	   fprintf(stderr, TAG"child signal %d\n", WTERMSIG(status));
	if (WCOREDUMP(status))
	   fprintf(stderr, TAG"child core dumped\n");
    }
    return ok;
}

/* This code written in a rush. */
