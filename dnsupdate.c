/* (c) 2008, Quest Software, Inc. All rights reserved. */

#include "common.h"

#include <vas.h>
#include <vas_gss.h>

#include "err.h"
#include "dns.h"
#include "dnsdebug.h"
#include "dnstcp.h"
#include "dnstkey.h"
#include "dnstsig.h"

/*
 * Dnyamic update of a VAS host's A entry in Active Directory DNS using
 * GSS TSIG for authentication.
 *
 * Useful for when DHCP is not provided by Active Directory, or the
 * host's DHCP client does not send option 81.
 *
 * This is the equivalent to Window's "ipconfig /registerdns" command.
 *
 * References:
 *  RFC 1034 Domain Names - Concepts and Facilities, 1987
 *  RFC 1035 Domain Names - Implementation and Specification, 1987
 *  RFC 1750 Randomness recommendations for security, 1994
 *  RFC 1995 Incremental Zone Transfer in DNS, 1996
 *  RFC 2136 Dynamic updates in the DNS (DNS UPDATE), 1997
 *  RFC 2535 DNS Security Extensions, 1999
 *  RFC 2845 Secret key transaction authentication for DNS (TSIG), 2000
 *  RFC 2930 Secret key establishment for DNS (TKEY), 2000
 *  RFC 3645 GSS algorithm for TSIG for DNS (GSS-TSIG), 2003
 *
 * See also:
 *  http://tools.ietf.org/wg/dhc/draft-ietf-dhc-fqdn-option
 *  http://technet2.microsoft.com/windowsserver/en/technologies/featured/dns/default.mspx
 */

/* TSIG algorithm names */
#define GSS_MICROSOFT_COM	"gss.microsoft.com"
#define GSS_TSIG		"gss-tsig"

/* An authentication context structure for convenience */
struct verify_context {
    vas_ctx_t *vasctx;	        /* VAS context */
    gss_ctx_id_t gssctx;	/* Our security context */
    const char *key_name;	/* The shared name of the context */
};

/* Prototypes */
static uint16_t  unique_id(void);
static int	 name_eq(const char *a, const char *b);
static void	 make_key_name(const char *fqdn, char *buf, size_t bufsz);
static void	 print_gss_error(const char *msg, struct verify_context *ctx,
       			OM_uint32 major, OM_uint32 minor);
static int	 verify(const void *buf, size_t buflen, const char *key_name,
       			const struct dns_tsig *tsig, void *context);
static void	*sign(struct dns_tsig *tsig, void *data, size_t datalen,
       			void *context);
static int	 update(int s, struct verify_context *vctx, const char *fqdn,
       			uint16_t utype, uint16_t uclass, uint32_t uttl,
		       	const void *udata, size_t udatalen, 
			const char *auth_domain);
static int	 gss_update(vas_ctx_t *ctx, vas_id_t *id, int s, 
			const char *server, const char *fqdn, 
			const char *domain, uint16_t utype, uint16_t uclass, 
			uint32_t uttl, const void *udata, size_t udatalen,
			const char *auth_domain);
static int	 my_inet_aton(const char *s, unsigned char *ipaddr, 
                        size_t ipaddrsz);


static uint16_t next_id;			/* used by unique_id() */
int vflag;					/* Verbose flag */
int Iflag;                                      /* IETF-compliance flag */
const char *tsig_name = GSS_MICROSOFT_COM;	/* Signature standard */

/* Initialises the unique ID stream */
void
init_unique_id()
{
    srandom(time(0) * getpid());
    next_id = random();
}

/* Returns a unique message ID for this session */
static uint16_t
unique_id()
{
    return next_id++;
}

/* Returns true if two DNS names are the same */
static int
name_eq(const char *a, const char *b)
{
    return strcmp(a, b) == 0;
}

/* Constructs a random key name for TKEY */
static void
make_key_name(const char *fqdn, char *buf, size_t bufsz)
{
    int i;
    static const char domainchars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	                      "abcdefghijklmnopqrstuvwxyz"
			      "0123456789-";

    /* Choose a random key for the TKEY */
    assert(bufsz > 31);
    for (i = 0; i < 31; i++)
	buf[i] = domainchars[random() % (sizeof domainchars - 1)];
    if (Iflag)
        snprintf(buf + 31, bufsz- 31, ".%s", fqdn);
    else
        buf[i] = 0;
    if (vflag)
	fprintf(stderr, "using TKEY %s\n", buf);
}

/* Prints a GSS error message to standard error */
static void
print_gss_error(const char *msg, struct verify_context *ctx, 
		OM_uint32 major, OM_uint32 minor)
{
    OM_uint32 eminor, emajor, ectx;
    gss_buffer_desc ebuf;

    fprintf(stderr, "gss_verify_mic: failed");
    ectx = 0;
    do {
	emajor = gss_display_status(&eminor, major, GSS_C_GSS_CODE,
		GSS_C_NO_OID, &ectx, &ebuf);
	if (GSS_ERROR(emajor)) errx(1, "gss_display_status: %d", emajor);
	fprintf(stderr, "\n  %.*s", ebuf.length, (char *)ebuf.value);
	(void)gss_release_buffer(&eminor, &ebuf);
    } while (ectx);
    do {
	emajor = gss_display_status(&eminor, minor, GSS_C_MECH_CODE,
		GSS_C_NO_OID, &ectx, &ebuf);
	if (GSS_ERROR(emajor)) errx(1, "gss_display_status: %d", emajor);
	fprintf(stderr, "\n    %.*s", ebuf.length, (char *)ebuf.value);
	(void)gss_release_buffer(&eminor, &ebuf);
    } while (ectx);
    fprintf(stderr, "\n");
}

/* Verifies a buffer using a TSIG-GSS MAC. Returns true if verified OK */
static int
verify(const void *buf, size_t buflen, const char *key_name, 
	const struct dns_tsig *tsig, void *context)
{
    struct verify_context *ctx = (struct verify_context *)context;
    OM_uint32 minor, major;
    gss_buffer_desc msgbuf, tokbuf;
    gss_qop_t qop;

    if (!name_eq(key_name, ctx->key_name))
	return 0;

    msgbuf.value = (void *)buf;
    msgbuf.length = buflen;
    tokbuf.value = (void *)tsig->mac;
    tokbuf.length = tsig->maclen;

    major = gss_verify_mic(&minor, ctx->gssctx, &msgbuf, &tokbuf, &qop);
    if (GSS_ERROR(major)) {
	print_gss_error("gss_verify_mic: failed", ctx, major, minor);
	if (vflag) {
	    fprintf(stderr, "mac used was:\n");
	    dumphex(tokbuf.value, tokbuf.length);
	    fprintf(stderr, "msg used was:\n");
	    dumphex(msgbuf.value, msgbuf.length);
	}
	return 0;
    }

    return 1;
}

/* Signs a buffer using a TSIG-GSS record. Returns the MAC data */
static void *
sign(struct dns_tsig *tsig, void *data, size_t datalen, void *context)
{
    struct verify_context *ctx = (struct verify_context *)context;
    gss_buffer_desc msgbuf, tokbuf;
    OM_uint32 minor, major;
    void *mac;

    msgbuf.value = data;
    msgbuf.length = datalen;

    major = gss_get_mic(&minor, ctx->gssctx, 0, &msgbuf, &tokbuf);
    if (GSS_ERROR(major)) {
	print_gss_error("gss_get_mic: cannot sign", ctx, major, minor);
	errx(1, "gss_get_mic");
    }

    if (vflag)
	fprintf(stderr, "sign: signed %u bytes of data -> %u byte mic\n",
	    msgbuf.length, tokbuf.length);

    mac = malloc(tokbuf.length);
    memcpy(mac, tokbuf.value, tokbuf.length);
    tsig->maclen = tokbuf.length;
    gss_release_buffer(&minor, &tokbuf);
    tsig->mac = mac;

    return mac;
}

/*
 * Perform a DNS query
 * We're only interested in the authoritative response; we don't actually
 * care if the name is there or not..
 * Returns 0 on success, and assigns a string to auth_domain.
 */
static int
query_auth(int s, const char *fqdn, uint16_t utype, uint16_t uclass,
	char **auth_domain_ret)
{
    struct dns_msg *msg = NULL;
    struct dns_header header, rheader;
    struct dns_rr zonerr, authrr, rr;
    char buffer[32768];
    int len;
    int rcode = -1;

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_QUERY;
    header.recurse_desired = 1; /* Don't care how we get it */

    /* Questions */
    header.qdcount++;
    memset(&zonerr, 0, sizeof zonerr);
    dns_rr_set_name(&zonerr, fqdn);
    zonerr.type = utype;
    zonerr.class_ = uclass;

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);
    dns_wr_question(msg, &zonerr);
    dns_wr_finish(msg);

    if (vflag)
	fprintf(stderr, "sending query...\n");
    dnstcp_sendmsg(s, msg);

    if (vflag) {
	if (vflag > 1) {
	    dumpmsg(msg);
	    fprintf(stderr, "\n");
	}
	fprintf(stderr, "waiting for query reply\n");
    }

    len = dnstcp_recv(s, buffer, sizeof buffer);
    if (len <= 0) {
	fprintf(stderr, "no reply to query?\n");
	goto fail;
    }
    dns_msg_setbuf(msg, buffer, len);

    if (vflag > 1) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }

    dns_rd_header(msg, &rheader);
    if (rheader.id != header.id || rheader.opcode != DNS_OP_QUERY) {
	fprintf(stderr, "bad reply to query\n");
	goto fail;
    }

    /* We don't actually care what the server's response is.
     * We only want the authority records */
    if (vflag)
	fprintf(stderr, "server response: %s\n",
	    dns_rcode_name(rheader.rcode));

    if (!rheader.nscount) {
	if (vflag)
	    fprintf(stderr, "no authority records returned\n");
	goto fail;
    }

    /* Skip some RRs */
    while (rheader.qdcount--) 
	dns_rd_question(msg, &rr);
    while (rheader.ancount--) 
	dns_rd_rr_head(msg, &rr);
    
    dns_rd_rr_head(msg, &authrr);
    *auth_domain_ret = strdup(authrr.name);

    rcode = 0;
    /* Fallthrough to return success */

fail:
    if (msg)
	dns_msg_free(msg);
    return rcode;

}

/*
 * Perform a DNS update
 * udata is treated as binary, unless udatalen is -1, in which case
 * udata is treated as a domain name.
 * Returns 0 on success, -1 on general error, otherwise a DNS rcode
 */
static int
update(int s, struct verify_context *vctx, 
	const char *fqdn, uint16_t utype, uint16_t uclass, 
	uint32_t uttl, const void *udata, size_t udatalen,
	const char *auth_domain)
{
    struct dns_msg *msg;
    struct dns_header header, rheader;
    struct dns_rr zonerr, prerr, delrr, addrr;
    char buffer[32768];
    int len;
    int rcode = -1;

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_UPDATE;

    /* Questions [=Zones affected] */
    header.qdcount++;
    memset(&zonerr, 0, sizeof zonerr);
    dns_rr_set_name(&zonerr, auth_domain);
    zonerr.type = DNS_TYPE_SOA;
    zonerr.class_ = DNS_CLASS_IN;

    /* Answers [=Prerequisites] */
    header.ancount++;
    memset(&prerr, 0, sizeof prerr);
    dns_rr_set_name(&prerr, auth_domain);
    prerr.type = DNS_TYPE_ANY;
    prerr.class_ = DNS_CLASS_ANY;

    /* Authoritatives [=Updates] */
    header.nscount++;
    memset(&delrr, 0, sizeof delrr);		/* Delete existing classes */
    dns_rr_set_name(&delrr, fqdn);
    delrr.type = utype;
    delrr.class_ = DNS_CLASS_ANY;

    if (udata) {
	header.nscount++;
	memset(&addrr, 0, sizeof addrr);	/* Add specific class */
	dns_rr_set_name(&addrr, fqdn);
	addrr.type = utype;
	addrr.class_ = uclass;
	addrr.ttl = uttl;
    }

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);
    dns_wr_question(msg, &zonerr);
    dns_wr_rr_head(msg, &prerr);
    dns_wr_data(msg, NULL, 0);
    dns_wr_rr_head(msg, &delrr);
    dns_wr_data(msg, NULL, 0);
    if (udata) {
	dns_wr_rr_head(msg, &addrr);
	if (udatalen == -1) {	/* If udatalen == -1, then its a domain name */
	    uint16_t mark;
	    dns_wr_begin(msg, &mark);
	    dns_wr_name(msg, udata);
	    dns_wr_end(msg, &mark);
	} else
	    dns_wr_data(msg, udata, udatalen);
    }

    if (vctx)
	dns_tsig_sign(msg, vctx->key_name, tsig_name, 36000, NULL, 0,
		sign, vctx);
    dns_wr_finish(msg);

    if (vflag)
	fprintf(stderr, "sending update...\n");
    dnstcp_sendmsg(s, msg);

    if (vflag) {
	if (vflag > 1) {
	    dumpmsg(msg);
	    fprintf(stderr, "\n");
	}
	fprintf(stderr, "waiting for update reply\n");
    }

    len = dnstcp_recv(s, buffer, sizeof buffer);
    if (len <= 0) {
	fprintf(stderr, "no reply to update?\n");
	goto fail;
    }
    dns_msg_setbuf(msg, buffer, len);

    if (vflag > 1) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }

    dns_rd_header(msg, &rheader);
    if (rheader.id != header.id || rheader.opcode != DNS_OP_UPDATE) {
	fprintf(stderr, "bad reply to update request\n");
	goto fail;
    }
    if (vflag)
	fprintf(stderr, "server response: %s\n",
	    dns_rcode_name(rheader.rcode));
    if (rheader.rcode != DNS_NOERROR) {
	fprintf(stderr, "error: server failed to update: %s\n",
	    dns_rcode_name(rheader.rcode));
	rcode = rheader.rcode;
	goto fail;
    }

#if 0					/* XXX always GSS_S_BAD_MIC? */
    /* Verify response */
    if (vctx) {
	dns_msg_setbuf(msg, buffer, len);
	dns_tsig_verify(msg, verify, vctx);
	if (vflag)
	    fprintf(stderr, "server response verified\n");
    } 
#endif

    dns_msg_free(msg);
    return 0;

fail:
    dns_msg_free(msg);
    return rcode;
}

/* 
 * Negotiate a GSS TKEY, and then call update()
 * Returns 0 on success, -1 on internal failure, otherwise a DNS rcode.
 */
static int
gss_update(vas_ctx_t *ctx, vas_id_t *id, int s,
	const char *server, const char *fqdn, const char *domain,
	uint16_t utype, uint16_t uclass, uint32_t uttl,
	const void *udata, size_t udatalen, const char *auth_domain)
{
    char buffer[32768];
    struct dns_rr rr, question;
    struct dns_header header;
    int bufferlen;
    int rcode = -1;

    char key_name[256];
    char server_principal[2048];
    gss_ctx_id_t gssctx;
    gss_buffer_desc intok, outtok;
    OM_uint32 major, minor;
    struct dns_tkey tkey;
    struct verify_context vctx;

    make_key_name(fqdn, key_name, sizeof key_name);

    /* The domain server's principal name */
    if (domain)
       snprintf(server_principal, sizeof server_principal,
	    "dns/%s@%s", server, domain);
    else
       snprintf(server_principal, sizeof server_principal,
	    "dns/%s", server);
    if (vflag)
	fprintf(stderr, "target service: %s\n", server_principal);

    /* Perform the GSS rounds */
    gssctx = GSS_C_NO_CONTEXT;
    intok.length = 0;
    intok.value = NULL;
    outtok.length = 0;
    outtok.value = NULL;
    for (;;) {
	major = vas_gss_spnego_initiate(ctx, id, NULL, &gssctx,
		server_principal,
	       	GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG |
		GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG,
		VAS_GSS_SPNEGO_ENCODING_DER, intok.length ? &intok : NULL,
		&outtok);
	if (GSS_ERROR(major)) {
	    warn("vas_gss_spnego_initiate: %s", vas_err_get_string(ctx, 1));
	    goto fail;
	}
	assert(major == GSS_S_CONTINUE_NEEDED || major == GSS_S_COMPLETE);

	if (outtok.value && outtok.length) {
	    struct dns_msg *msg = dns_msg_new();

	    dns_msg_setbuf(msg, buffer, sizeof buffer);
	    memset(&header, 0, sizeof header);
	    header.id = unique_id();
	    header.opcode = DNS_OP_QUERY;

	    /* Questions */
	    header.qdcount++;
	    memset(&question, 0, sizeof question);
	    dns_rr_set_name(&question, key_name);
	    question.type = DNS_TYPE_TKEY;
	    question.class_ = DNS_CLASS_IN;

	    /* Answers */
	    header.ancount++;
	    memset(&rr, 0, sizeof rr);
	    dns_rr_set_name(&rr, key_name);
	    rr.type = DNS_TYPE_TKEY;
	    rr.class_ = DNS_CLASS_ANY;
	    rr.ttl = 0;
	    memset(&tkey, 0, sizeof tkey);
	    snprintf(tkey.algorithm, sizeof tkey.algorithm, "%s",
		    tsig_name);
	    tkey.inception = time(0);
	    tkey.expiration = tkey.inception + 2*60*60;
	    tkey.mode = DNS_TKEY_MODE_GSSAPI;
	    tkey.key = outtok.value;
	    tkey.keysz = outtok.length;

	    /* Build DNS packet */
	    dns_wr_header(msg, &header);
	    dns_wr_question(msg, &question);
	    dns_wr_rr_head(msg, &rr);
	    dns_tkey_wr(msg, &tkey);
	    dns_wr_finish(msg);

	    if (vflag)
		fprintf(stderr, "sending tkey query\n");
	    bufferlen = dnstcp_sendmsg(s, msg);
	    if (bufferlen == -1)
		goto fail;

	    if (vflag > 1) {
		dumpmsg(msg);
		fprintf(stderr, "\n");
	    }

	    dns_msg_free(msg);
	    (void)gss_release_buffer(&minor, &outtok);
	} else {
	    if (vflag > 1)
		fprintf(stderr, "no output token needed after this round\n");
	}

	if (major == GSS_S_CONTINUE_NEEDED) {
	    struct dns_msg *msg = dns_msg_new();
	    struct dns_header recv_header;

	    if (vflag)
		fprintf(stderr, "waiting for tkey reply\n");
	    bufferlen = dnstcp_recv(s, buffer, sizeof buffer);
	    if (bufferlen <= 0)
		goto fail;
	    dns_msg_setbuf(msg, buffer, bufferlen);

	    if (vflag > 1) {
		dumpmsg(msg);
		fprintf(stderr, "\n");
	    }

	    dns_rd_header(msg, &recv_header);
	    assert(recv_header.id == header.id);
	    assert(recv_header.response);
	    assert(recv_header.opcode == DNS_OP_QUERY);
	    assert(!recv_header.truncated);
	    if (recv_header.rcode != 0) {
		fprintf(stderr, "could not negotiate GSS context: %s\n",
			dns_rcode_name(recv_header.rcode));
		rcode = recv_header.rcode;
		goto fail;
	    }

	    /* Check the question back is the same */
	    assert(recv_header.qdcount == 1);
	    dns_rd_question(msg, &question);
	    assert(name_eq(question.name, key_name));
	    assert(question.type == DNS_TYPE_TKEY);
	    assert(question.class_ == DNS_CLASS_IN);

	    /* Check that the answer is a TKEY */
	    assert(recv_header.ancount == 1);
	    dns_rd_rr_head(msg, &rr);
	    assert(name_eq(rr.name, key_name));
	    assert(rr.type == DNS_TYPE_TKEY);
	    assert(rr.class_ == DNS_CLASS_IN || 
		   rr.class_ == DNS_CLASS_ANY);
	    dns_tkey_rd(msg, &tkey);
	    assert(name_eq(tkey.algorithm, tsig_name));
	    assert(tkey.expiration > time(0));
	    assert(tkey.mode == DNS_TKEY_MODE_GSSAPI);
	    assert(tkey.error == DNS_NOERROR);
	    intok.value = tkey.key;
	    intok.length = tkey.keysz;

	    dns_msg_free(msg);
	} else
	    break;
    }
    if (vflag)
	fprintf(stderr, "gss context established\n");

    vctx.vasctx = ctx;
    vctx.gssctx = gssctx;
    vctx.key_name = key_name;

    /* Verify the final TSIG */
    if (bufferlen) {
	struct dns_msg *msg = dns_msg_new();
	dns_msg_setbuf(msg, buffer, bufferlen);
	dns_tsig_verify(msg, verify, &vctx);
	dns_msg_free(msg);
	if (vflag)
	    fprintf(stderr, "TSIG verified\n");
    } else
	errx(1, "final TSIG from server was not signed");

    return update(s, &vctx, fqdn, utype, uclass, uttl, udata, 
	    udatalen, auth_domain);

fail:
    return rcode;
}

/*
 * Convert a string containing an IP address e.g "12.34.56.67" 
 * into a unsigned char[4]. Returns true if the conversion
 * completed successfully.
 */
static int
my_inet_aton(const char *s, unsigned char *ipaddr, size_t ipaddrsz)
{
    unsigned int octet[4];

    assert(ipaddrsz == 4 * sizeof (unsigned char));
    if (sscanf(s, "%u.%u.%u.%u", octet, octet+1, octet+2, octet+3) != 4 ||
	octet[0] > 255 || octet[1] > 255 ||
	octet[2] > 255 || octet[3] > 255)
	    return 0;
    ipaddr[0] = octet[0];
    ipaddr[1] = octet[1];
    ipaddr[2] = octet[2];
    ipaddr[3] = octet[3];
    return 1;
}

int
main(int argc, char **argv)
{
    int s;
    char **servers, **serverp;
    vas_ctx_t *vas_ctx = NULL;
    vas_err_t error;
    char *domain = NULL;
    char *fqdn = NULL;
    char *nameserver=NULL;
    char *spn = "host/";
    int ret;
    vas_id_t *local_id;
    vas_computer_t *local_computer;
    unsigned char ipaddr[4];
    char *user_servers[2];
    unsigned int ttl = 60*60;
    int ch;
    int opterror = 0;
    int Nflag = 0;
    int rflag = 0;
    uint16_t utype;
    const void *udata;
    const char *name;
    const char *auth_domain = NULL;
    size_t udatalen;
    char reverse[4 * 4 + sizeof "IN-ADDR.ARPA"];

    /* Argument processing */
    while ((ch = getopt(argc, argv, "a:d:h:INrs:t:v")) != -1)
	switch (ch) {
	case 'a':
	    auth_domain = strdup(optarg);
	    break;
	case 'd':
	    domain = strdup(optarg);
	    break;
	case 'h':
	    fqdn = optarg;
	    break;
	case 'I':
	    tsig_name = GSS_TSIG;
            Iflag = 1;
	    break;
	case 'N':
	    Nflag = 1;
	    break;
	case 'r':		    /* Update reverse PTR record instead */
	    rflag = 1;
	    break;
	case 's':
	    nameserver = optarg;
	    break;
	case 't':
	    ttl = atoi(optarg);
	    if (!ttl && strcmp(optarg, "0") != 0) {
		fprintf(stderr, "bad ttl number\n");
		opterror = 1;
	    }
	    break;
	case 'v':
	    vflag++;
	    break;
	default:
	    opterror = 1;
	    break;
	}

    if (!(optind < argc && my_inet_aton(argv[optind++], ipaddr, sizeof ipaddr)))
	opterror = 1;

    if (optind != argc)
	opterror = 1;

    if (opterror) {
	fprintf(stderr, "usage: %s"
			" [-d domain]"
			" [-h hostname]"
			" [-I]"
			" [-N]"
			" [-r]"
			" [-s nameserver]"
		        " [-t ttl]"
	       		" [-v]"
			" ipaddr\n", argv[0]);
	exit(2);
    }

    if (vflag) {
	fprintf(stderr, "dnsupdate %s\n", PACKAGE_VERSION);
	fprintf(stderr, "spn: %s\n", spn);
	fprintf(stderr, "ttl: %u\n", ttl);
	fprintf(stderr, "ipaddr: %u.%u.%u.%u\n", 
		ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    }

    /* Initialise random number generator */
    init_unique_id();

    if (!Nflag) {

        /* Initialise VAS */
        error = vas_ctx_alloc(&vas_ctx);
        if (error != VAS_ERR_SUCCESS)
            errx(1, "vas_ctx_alloc");

        error = vas_id_alloc(vas_ctx, spn, &local_id);
        if (error)
            errx(1, "vas_id_alloc: %s", vas_err_get_string(vas_ctx, 1));

        error = vas_id_establish_cred_keytab(vas_ctx, local_id,
                VAS_ID_FLAG_USE_MEMORY_CCACHE, NULL);
        if (error)
            errx(1, "vas_id_establish_cred_keytab: %s", 
                    vas_err_get_string(vas_ctx, 1));

        error = vas_gss_initialize(vas_ctx, local_id);
        if (error)
            errx(1, "vas_gss_initialize: %s", 
                    vas_err_get_string(vas_ctx, 1));

        /* Determine the fully qualified domain name to use */
        if (!fqdn) {
            error = vas_computer_init(vas_ctx, local_id, spn, 
                            VAS_NAME_FLAG_NO_IMPLICIT, &local_computer);
            if (error)
                errx(1, "vas_computer_init: %s", vas_err_get_string(vas_ctx, 1));

            error = vas_computer_get_dns_hostname(vas_ctx, local_id, local_computer,
                    &fqdn);
            if (error)
                errx(1, "vas_computer_get_dns_hostname: %s",
                        vas_err_get_string(vas_ctx, 1));
        }

        /* Determine the realm/domain to use */
        if (!domain) {
            error = vas_info_joined_domain(vas_ctx, &domain, NULL);
            if (error)
                errx(1, "vas_info_joined_domain: %s", 
                        vas_err_get_string(vas_ctx, 1));
        }
    }

    if (!fqdn)
        errx(1, "Cannot determine fully-qualified hostname; specify with -h <hostname>");

    if (!domain)
	errx(1, "Cannot determine domain name; specify with -d <domain>");

    if (vflag) {
	fprintf(stderr, "hostname: %s\n", fqdn);
	fprintf(stderr, "domain: %s\n", domain);
    }

    /* Determine the list of possible nameservers to use */
    if (nameserver) {
	user_servers[0] = nameserver;
	user_servers[1] = NULL;
	servers = user_servers;
    } else if (!vas_ctx)
        errx(1, "Cannot determine nameserver; specify with -s");
    else {
	error = vas_info_servers(vas_ctx, NULL, NULL, VAS_SRVINFO_TYPE_DC,
		&servers);
	if (error)
	    errx(1, "vas_info_servers: %s", vas_err_get_string(vas_ctx, 1));
    }

    if (rflag)  {
	snprintf(reverse, sizeof reverse,
		"%u.%u.%u.%u.IN-ADDR.ARPA",
		ipaddr[3], ipaddr[2], ipaddr[1], ipaddr[0]);
	name = reverse;
	utype = DNS_TYPE_PTR;
	udata = fqdn;
	udatalen = -1;
	if (vflag)
	    fprintf(stderr, "reverse: %s\n", reverse);
    } else {
	name = fqdn;
	utype = DNS_TYPE_A;
	udata = ipaddr;
	udatalen = sizeof ipaddr;
    }

    if (vflag)
	fprintf(stderr, "auth_domain: %s\n", auth_domain);

    /* Try each nameserver, until one works */
    ret = 0;
    for (serverp = servers; *serverp; serverp++) {
	if (vflag)
	    fprintf(stderr, "trying %s...\n", *serverp);
	s = dnstcp_connect(*serverp);
	if (s != -1) {
	    char *auth = (char *)auth_domain;

	    if (!auth) {
		/* Try and look up the authoritative domain name */
		/* Note that Windows DNS will not return authority
		 * records if you do a PTR query */
		query_auth(s, name, DNS_TYPE_A, DNS_CLASS_IN, &auth);
		if (vflag)
		    fprintf(stderr, "authoritative domain for %s: %s\n", 
			    name, auth ? auth : "(none)");
		if (!auth) {
		    fprintf(stderr, "%s: no authoritative domain for %s\n",
			    *serverp, name);
		    ret = -1;
		    goto done;
		}
	    }

            if (Nflag)
		/* Perform an UN-authenticated update */
                ret = update(s, NULL, name, utype, DNS_CLASS_IN,
                        ttl, udata, udatalen, auth);
            else
		/* Perform an authenticated update */
                ret = gss_update(vas_ctx, local_id, s, *serverp, name, 
                        domain, utype, DNS_CLASS_IN, ttl, udata, 
                        udatalen, auth);
done:
	    dnstcp_close(&s);
	    if (auth && auth != auth_domain)
		free(auth);
	    if (ret == 0)
		break;
	}
    }
    if (!ret)
	warnx("could not connect to any nameservers");

    if (vas_ctx) {
        if (!nameserver)
            vas_info_servers_free(vas_ctx, servers);
        vas_ctx_free(vas_ctx);
    }

    exit(ret ? 0 : 1);
}
