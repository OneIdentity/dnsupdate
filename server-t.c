/*
 * A test DNS server.
 *
 * This tool is used to test DNS clients. 
 *
 * It receives a DNS query on stdin, and checks that it matches the request
 * pattern provided by the first command line argument.
 * Then it replies (on stdin) with a packet constructed from the response
 * pattern given by the second argument.
 * This continues for successive pairs of arguments on the command line,
 * until none are left, in which case it waits for the client to close
 * the connection and then exits with a success code.
 *
 * The program exits with success only if all received requests match 
 * and there were no other errors sending the responses.
 *
 *
 * EXAMPLE
 *
 * Here is a simple example of a arguments to service a single
 * IP address lookup for a given domain and the sending back of a valid 
 * response.
 *
 *    'Q:foo.example.com A' 'OK:foo.example.com A 1.2.3.4'
 *
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
 * The response patterns begins with an error code (usually 'OK' indicating
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

int verbose = 0;

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
    { "ANY", DNS_CLASS_ANY },
    { 0 }
};

/* Return true if the string bound by start,end is the same as the string */
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
	fprintf(stderr, "wr_response '%s'\n", pattern);

    /* Read the header from the query to become the reply header */
    dns_rd_header(qmsg, &header);

    /* Always set the response bit */
    header.response = 1;

    /* Read the opcode from the beginning of the pattern */
    p = pattern;
    while (*p && *p != ':' && *p != '+' && *p != '-')
	p++;
    if (p != pattern)
	header.opcode = DNS_NOERROR;
    else
	header.opcode = lookup(pattern, p, lookup_rcode);

    if (verbose > 2)
	fprintf(stderr, "  header.opcode %u\n", header.opcode);

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
	    fprintf(stderr, "   section %d\n", section);

	/* Convenience macros. Yucky, but "testing-quality". */
/* skip over spaces */
#define SKIPSPACE(p) while (*p == ' ') p++
/* skip over numbers */
#define SKIPNUMBER(p) while (*p >= '0' && *p <= '9') p++
/* skip over a non-whitespace word, not including ':' or ',' */
#define SKIPWORD(p)  while (*p && *p != ',' && *p != ' ' && *p != ':') p++
/* Read and skip a domain name into a char buffer. Nul terminate it */
#define SKIPNAME(p, name) do { \
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
	    errx(1, "bad integer"); \
    } while (0)
/* Read and skip an integer in base 10, or default to a value */
#define SKIPI32D(p, i, dfl) do { \
	if (*p >= '0' && *p <= '9') \
	    SKIPI32(p, i); \
	else \
	    i = dfl; \
    } while (0)

	/* Read the resource name */
	SKIPNAME(p, rr.name);

	if (verbose > 2)
	    fprintf(stderr, "     rr.name '%s'\n", rr.name);

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
	    fprintf(stderr, "     rr.ttl %u\n", rr.ttl);

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
	    fprintf(stderr, "     rr.class_ %u\n", rr.class_);

	/* Look up the symbol as a type */
	i = lookup(start, p, lookup_type);
	if (i == -1)
	    errx(1, "unknown type '%.*s'", p-start, start);
	rr.type = i;
	if (verbose > 2)
	    fprintf(stderr, "     rr.type %u\n", rr.type);
	SKIPSPACE(p);

	/* We have a full record header now, so write it and begin
	 * the data portion */
	dns_wr_rr_head(rmsg, &rr);
	dns_wr_begin(rmsg, &mark);

	/* Write the RDATA part of the resource depending on the type */
	switch (rr.type) {
	case DNS_TYPE_A: {
	    /* IPv4 address */
	    unsigned char addr[4];
	    uint32_t n;
	    if (verbose > 3)
		fprintf(stderr, "     writing IPv4 address for A class\n");
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
	fprintf(stderr, "match_query pattern '%s'\n", pattern);

    dns_rd_header(qmsg, &header);

    /* If the message is a reponse, then fail immediately. 
     * We want a 'query' packet */
    if (header.response) {
	fprintf(stderr, "header match failed: response!\n");
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
	    fprintf(stderr, "  testing header flag %c == %u\n", *p, expected);
	if (actual != expected) {
	    fprintf(stderr, "flag %c%c match failed\n",
		    expected ? '+' : '-', *p);
	    return 0;
	}
	p++;
    }

    section = 0;
    records_left = 0;
    while (*p) {
	switch (*p) {
	case ':': 
	    recno = 0;
	    if (records_left) {
		fprintf(stderr, "unmatched records in %s section\n",
		   section_name[section]);
		return 0;
	    }
	    section++;
	    records_left = 
		   section == 1 ? header.qdcount :
		   section == 2 ? header.ancount :
		   section == 3 ? header.nscount :
		   section == 4 ? header.arcount : -1;
	    break;
	case ',':
	    recno++;
	    break;
	default:
	    errx(1, "unexpected pattern char 0x%02x '%c'", *p, *p);
	}
	p++;
	if (*p == ':')
	    continue;

	if (verbose > 2)
	    fprintf(stderr, "  section %d (records_left %d)\n", section, records_left);

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
	    fprintf(stderr, "  pattern '%.*s'\n", (int)(patend - patstart), patstart);

	/* Check that there are records left to match */
	if (!records_left--) {
	    fprintf(stderr, "%.*s: not enough records in %s section\n",
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
		fprintf(stderr, "    '*' matches any resource\n");
	    if (section > 1)
		dns_rd_skip(qmsg, dns_rd_uint16(qmsg));
	    p++;
	    continue;
	}

	/* Read the name from the query */
	SKIPNAME(p, rm.name);
	SKIPSPACE(p);
	if (strcmp(rm.name, "?") == 0) {
	    if (verbose > 2)
		fprintf(stderr, "    '?' matches name '%s'\n", rm.name);
	} else if (strcmp(rr.name, rm.name) == 0) {
	    if (verbose > 2)
		fprintf(stderr, "    pattern matches name '%s'\n", rm.name);
	} else {
	    fprintf(stderr, "%.*s: name mismatch: %s (%s:%d)\n",
		    (int)(patend - patstart), patstart, rr.name,
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
		    fprintf(stderr, "    matching ttl %u\n", rm.ttl);
		if (rm.ttl != rr.ttl) {
		    fprintf(stderr, "%.*s: ttl mismatch: %d (%s:%d)\n",
			    (int)(patend - patstart), patstart, rr.ttl,
			    section_name[section], recno);
		    return 0;
		}
	    }
	}

	/* Read the next symbol which is either a class or a type */
	start = p; SKIPWORD(p);
	i = lookup(start, p, lookup_class);
	if (i == -1) {
	    if (verbose > 2)
		fprintf(stderr, "  no class in pattern; actual %s\n",
			unlookup(rr.class_, lookup_class));
	} else {
	    if (verbose > 2)
		fprintf(stderr, 
			"  matching pattern class %s against actual %s\n",
			unlookup(rm.class_, lookup_class),
			unlookup(rr.class_, lookup_class));
	    if (rm.class_ != rr.class_) {
		fprintf(stderr, "%.*s: class mismatch: %s (%s:%d)\n",
			(int)(patend - patstart), patstart, 
			unlookup(rr.class_, lookup_class),
			section_name[section], recno);
		return 0;
	    }
	    /* It was recognised as a class, so read the next symbol */
	    rm.class_ = i;
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
	    fprintf(stderr, "  matching pattern type %s against actual %s\n",
		    unlookup(rm.type, lookup_type),
		    unlookup(rr.type, lookup_type));
	if (rm.type != rr.type) {
	    fprintf(stderr, "%.*s: type mismatch: %s (%s:%d)\n",
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
	switch (rm.type) {
	case DNS_TYPE_A: {
	    /* IPv4 address */
	    unsigned char maddr[4];
	    unsigned char raddr[4];
	    uint32_t n;
	    if (dns_rd_remain(qmsg) != 4) {
		fprintf(stderr, "bad A record size %d (%s:%d)\n",
			dns_rd_remain(qmsg),
			section_name[section], recno);
		return 0;
	    }
	    dns_rd_data(qmsg, raddr, sizeof raddr);
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
	       fprintf(stderr,"%.*s: A address mismatch: %d.%d.%d.%d (%s:%d)\n",
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
	    if (strcmp(rm.name, "?") != 0 && strcmp(rr.name, rm.name) != 0) {
		fprintf(stderr, "%.*s: value mismatch: %s (%s:%d)\n",
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
	    fprintf(stderr, "unexpected %d bytes remaining (%s:%d)\n",
		dns_rd_remain(qmsg),
		section_name[section], recno);
	    return 0;
	}
	dns_rd_end(qmsg);
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
	fprintf(stderr, "accepting on port %d\n", port);
    saddrlen = sizeof saddr;
    if ((t = accept(s, &saddr, &saddrlen)) < 0)
	err(1, "accept");
    if (verbose > 2)
	fprintf(stderr, "  accepted connection\n");
    if (close(s) < 0)
	warn("close s");
    if (verbose > 2)
	fprintf(stderr, "  returning socket %d\n", t);
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
	fprintf(stderr, "unexpected message recieved from client!\n");
	exit(1);
    }
    if (close(fd) < 0)
	err(1, "close");
}

int
main(int argc, char **argv)
{
    char inbuf[65535];
    char outbuf[65535];
    int inlen;
    struct dns_msg inmsg;
    struct dns_msg outmsg;
    extern char *optarg;
    extern int optind;
    int ch;
    int error = 0;
    int port = -1;
    int fd;

    while ((ch = getopt(argc, argv, "p:v")) != -1)
	switch (ch) {
	case 'p':
	    port = atoi(optarg);
	    break;
	case 'v':
	    verbose++;
	    break;
	default:
	    error = 1;
	}

    /* Must have a multiple of two arguments, and at least two */
    if (optind == argc || (argc - optind) % 2 != 0)
	error = 1;
    if (error) {
	fprintf(stderr, "usage: %s [-p port] query response ...\n", argv[0]);
	exit(1);
    }

    /* Use either stdin as a socket, or wait for a port connection */
    if (port == -1)
	fd = STDIN_FILENO;
    else
	fd = tcp_accept(port);

    /* Read a query */
    for (; optind < argc; optind += 2) {
	if (verbose > 2)
	    fprintf(stderr, "receiving message\n");
	inlen = dnstcp_recvmsg(fd, inbuf, sizeof inbuf, &inmsg);
	if (inlen < 0)
	    exit(1);
	if (verbose > 2)
	    fprintf(stderr, "  received message len %d\n", inlen);
	if (verbose)
	    dumpmsg(&inmsg);
	if (!match_query(&inmsg, argv[optind])) {
	    fprintf(stderr, "request failed to match '%s' (arg %d)\n", 
		    argv[optind], optind);
	    exit(1);
	}
	fprintf(stderr, "request:  '%s'\n", argv[optind]);
	/* Rewind the input message */
	dns_msg_setbuf(&inmsg, inbuf, inlen);
	/* Build the output message */
	dns_msg_setbuf(&outmsg, outbuf, sizeof outbuf);
	wr_response(&outmsg, &inmsg, argv[optind + 1]);
	fprintf(stderr, "response: '%s'\n", argv[optind + 1]);
	dns_wr_finish(&outmsg);
	if (verbose)
	    dumpmsg(&outmsg);
	/* Send the output message */
	if (dnstcp_sendmsg(fd, &outmsg) < 0)
	    exit(1);
    }

    tcp_wait_close(fd);

    exit(0);
}

