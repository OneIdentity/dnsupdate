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
#include "conf.h"
#include "list.h"
#include "resconf.h"

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

/* Values for UpdateSecurityLevel configuration */
#define SECURITY_ONLY_SECURE		256
#define SECURITY_ONLY_UNSECURE		16
#define SECURITY_UNSECURE_THEN_SECURE	0

/* Values for RegisterReverseLookup */
#define REGISTER_PTR_NEVER		0
#define REGISTER_PTR_ALWAYS		1
#define REGISTER_PTR_ONLY_IF_A_SUCCEEDS	2

/* Default cache TTL for updated records */
#define DEFAULT_TTL	(15 * 60)   /* 15 minutes */

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
			const char *serverspn, uint16_t utype, uint16_t uclass, 
			uint32_t uttl, const void *udata, size_t udatalen,
			const char *auth_domain);
static int	 my_inet_aton(const char *s, unsigned char *ipaddr, 
                        size_t ipaddrsz);


static uint16_t next_id;			/* used by unique_id() */
int verbose;					/* Verbose, higher value means more verbose */
int ietf_compliant;                             /* IETF-compliance flag */
const char *tsig_name = GSS_MICROSOFT_COM;	/* Signature standard */

static int random_fd = -1;

/* Initialises the unique ID stream */
void
init_unique_id()
{
    if ((random_fd = open("/dev/urandom", O_RDONLY)) < 0) {
	srandom(time(0) * getpid());
	next_id = random();
    }
}

/* Returns a unique message ID for this session */
static uint16_t
unique_id()
{
    uint16_t data;
    int len;

    if (random_fd == -1)
	return next_id++;

    if ((len = read(random_fd, &data, sizeof data)) < 0)
	err(1, "urandom");
    if (len != sizeof data)
	errx(1, "urandom short read");
    return data;
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
    if (ietf_compliant)
        snprintf(buf + 31, bufsz- 31, ".%s", fqdn);
    else
        buf[i] = 0;
    if (verbose)
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
	fprintf(stderr, "\n  %.*s", (int)ebuf.length, (char *)ebuf.value);
	(void)gss_release_buffer(&eminor, &ebuf);
    } while (ectx);
    do {
	emajor = gss_display_status(&eminor, minor, GSS_C_MECH_CODE,
		GSS_C_NO_OID, &ectx, &ebuf);
	if (GSS_ERROR(emajor)) errx(1, "gss_display_status: %d", emajor);
	fprintf(stderr, "\n    %.*s", (int)ebuf.length, (char *)ebuf.value);
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
	if (verbose > 1) {
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

    if (verbose > 1)
	fprintf(stderr, "sign: signed %d bytes of data -> %d byte mic\n",
	    (int)msgbuf.length, (int)tokbuf.length);

    mac = malloc(tokbuf.length);
    memcpy(mac, tokbuf.value, tokbuf.length);
    tsig->maclen = tokbuf.length;
    gss_release_buffer(&minor, &tokbuf);
    tsig->mac = mac;

    return mac;
}

/*
 * Queries the authoritative SOA record for a domain, and returns the domain 
 * and primary nameserver from the SOA record in the authority section. 
 * Expects an NXDOMAIN result. Returns 0 on success.
 */
static int
query_soa(int s, const char *fqdn, char *domain, size_t domainsz,
	char *primary, size_t primarysz)
{
    struct dns_msg *msg = NULL;
    struct dns_header header, rheader;
    struct dns_rr zonerr, rr;
    char buffer[32768];
    int len;
    int rcode = -1;

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_QUERY;
    header.authoritative = 1;	/* We want an authoritative answer */
    header.recurse_desired = 1; /* Don't care how we get it */

    /* Questions */
    header.qdcount++;
    memset(&zonerr, 0, sizeof zonerr);
    dns_rr_set_name(&zonerr, fqdn);
    zonerr.type = DNS_TYPE_SOA;
    zonerr.class_ = DNS_CLASS_IN;

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);
    dns_wr_question(msg, &zonerr);
    dns_wr_finish(msg);

    if (verbose)
	fprintf(stderr, "sending SOA query for %s...\n", fqdn);
    dnstcp_sendmsg(s, msg);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }
    if (verbose > 1)
	fprintf(stderr, "waiting for query reply\n");

    len = dnstcp_recv(s, buffer, sizeof buffer);
    if (len <= 0) {
	fprintf(stderr, "no reply to query?\n");
	goto fail;
    }
    dns_msg_setbuf(msg, buffer, len);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }

    dns_rd_header(msg, &rheader);
    /* Expect an NXDOMAIN QUERY response */
    if (rheader.id != header.id || rheader.opcode != DNS_OP_QUERY) {
	fprintf(stderr, "bad reply to query\n");
	goto fail;
    }
    if (verbose > 1 || (verbose && rheader.rcode))
	fprintf(stderr, "server response: %s\n",
	    dns_rcode_name(rheader.rcode));
    if (rheader.rcode != DNS_NXDOMAIN && rheader.rcode != DNS_NOERROR)
	goto fail;

    /* Skip question RRs */
    while (rheader.qdcount--) 
	dns_rd_question(msg, &rr);
    if (rheader.ancount) {
	fprintf(stderr, "unexpected answer record in reply\n");
	goto fail;
    }
    if (!rheader.nscount) {
	if (verbose)
	    fprintf(stderr, "no authority records returned for %s\n", fqdn);
	goto fail;
    }
    dns_rd_rr_head(msg, &rr);
    if (rr.type != DNS_TYPE_SOA) {
	fprintf(stderr, "expected an SOA record in reply\n");
	goto fail;
    }
    dns_rd_begin(msg);

    /* Copy the domain name from the RR header */
    if (domainsz  + 1 < strlen(rr.name))
	errx(1, "domainsz too small");
    strcpy(domain, rr.name);

    /* The next part of the resource record is the primary nameserver */
    dns_rd_name(msg, primary, primarysz);

    if (verbose) {
	fprintf(stderr, "domain: %s\n", domain);
	fprintf(stderr, "primary: %s\n", primary);
    }
    /* (We ignore the rest of the reply packet) */

    rcode = 0;
    /* Fallthrough to return success */

fail:
    if (msg)
	dns_msg_free(msg);
    return rcode;
}

/*
 * Queries the list of nameservers for the given domain.
 * Copies the nameserver entries out of all the NS records in the
 * answer section.
 */
static int
query_ns(int s, const char *domain, char ***list_ret)
{
    struct dns_msg *msg = NULL;
    struct dns_header header, rheader;
    struct dns_rr zonerr, rr;
    char buffer[32768];
    char name[DNS_MAXNAME];
    int len;
    int rcode = -1;
    char **list;

    list = list_new();
    if (!list)
	errx(1, "query_ns: cannot allocate list");

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_QUERY;
    header.authoritative = 1;	/* We want an authoritative answer */
    header.recurse_desired = 1; /* Don't care how we get it */

    /* Questions */
    header.qdcount++;
    memset(&zonerr, 0, sizeof zonerr);
    dns_rr_set_name(&zonerr, domain);
    zonerr.type = DNS_TYPE_NS;
    zonerr.class_ = DNS_CLASS_IN;

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);
    dns_wr_question(msg, &zonerr);
    dns_wr_finish(msg);

    if (verbose)
	fprintf(stderr, "sending NS query for %s...\n", domain);
    dnstcp_sendmsg(s, msg);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }
    if (verbose > 1)
	fprintf(stderr, "waiting for query reply\n");

    len = dnstcp_recv(s, buffer, sizeof buffer);
    if (len <= 0) {
	fprintf(stderr, "no reply to query?\n");
	goto fail;
    }
    dns_msg_setbuf(msg, buffer, len);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }

    dns_rd_header(msg, &rheader);
    /* Expect an NXDOMAIN QUERY response */
    if (rheader.id != header.id || rheader.opcode != DNS_OP_QUERY) {
	fprintf(stderr, "bad reply to query\n");
	goto fail;
    }
    if (verbose > 1 || (verbose && rheader.rcode))
	fprintf(stderr, "server response: %s\n",
	    dns_rcode_name(rheader.rcode));
    if (rheader.rcode != DNS_NOERROR)
	goto fail;

    /* Skip question RRs */
    while (rheader.qdcount--) 
	dns_rd_question(msg, &rr);
    if (!rheader.ancount) {
	if (verbose)
	    fprintf(stderr, "no answers returned for %s\n", domain);
	goto fail;
    }

    /* Add the answer records to a list */
    while (rheader.ancount--) {
	dns_rd_rr_head(msg, &rr);
	dns_rd_begin(msg);
	if (rr.type == DNS_TYPE_NS) {
	    dns_rd_name(msg, name, sizeof name);
	    if (verbose > 1)
		fprintf(stderr, " NS %s\n", name);
	    if (list_append(&list, name) < 0)
		goto fail;
	} else
	    fprintf(stderr, "non-NS record in reply\n");
	dns_rd_end(msg);
    }

    /* The rest of the packet is A addresses but we ignore those */

    rcode = 0;
    /* Fallthrough to return success */

fail:
    if (msg)
	dns_msg_free(msg);
    if (rcode == 0)
	*list_ret = list;
    else
	list_free(list);
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
    struct dns_rr rr;
    char buffer[32768];
    int len;
    int rcode = -1;
    int deleting = (uttl == 0);

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_UPDATE;

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);

    /* Questions [=Zones affected] */
    memset(&rr, 0, sizeof rr);
    dns_rr_set_name(&rr, auth_domain);
    rr.type = DNS_TYPE_SOA;
    rr.class_ = DNS_CLASS_IN;
    dns_wr_question(msg, &rr);
    dns_wr_inc_qdcount(msg);

    /* Answers [=Prerequisites] */
    if (1) {
	/* Require that there is no CNAME entry that trumps the A */
	memset(&rr, 0, sizeof rr);
	dns_rr_set_name(&rr, fqdn);
	rr.type = DNS_TYPE_CNAME;
	rr.class_ = DNS_CLASS_NONE;
	dns_wr_rr_head(msg, &rr);
	dns_wr_data(msg, NULL, 0);
	dns_wr_inc_ancount(msg);
    }

    /* Authoritatives [=Updates] */
    memset(&rr, 0, sizeof rr);
    dns_rr_set_name(&rr, fqdn);
    rr.type = utype;
    rr.class_ = DNS_CLASS_ANY;			/* Delete existing entry */
    dns_wr_rr_head(msg, &rr);
    dns_wr_data(msg, NULL, 0);
    dns_wr_inc_nscount(msg);

    if (!deleting) {
	/* Adding the new entry */
	memset(&rr, 0, sizeof rr);
	dns_rr_set_name(&rr, fqdn);
	rr.type = utype;
	rr.class_ = uclass;
	rr.ttl = uttl;
	dns_wr_rr_head(msg, &rr);
	if (udatalen == -1) {	/* If udatalen == -1, then its a domain name */
	    uint16_t mark;
	    dns_wr_begin(msg, &mark);
	    dns_wr_name(msg, udata);
	    dns_wr_end(msg, &mark);
	} else
	    dns_wr_data(msg, udata, udatalen);
	dns_wr_inc_nscount(msg);
    } else if (verbose > 1)
	fprintf(stderr, "update is a delete request: data ignored\n");

    if (vctx)
	dns_tsig_sign(msg, vctx->key_name, tsig_name, 36000, NULL, 0,
		sign, vctx);
    dns_wr_finish(msg);

    if (verbose > 1)
	fprintf(stderr, "sending %s update...\n",
		vctx ? "secure" : "unsecure");
    dnstcp_sendmsg(s, msg);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }
    if (verbose > 1) 
	fprintf(stderr, "waiting for update reply\n");

    len = dnstcp_recv(s, buffer, sizeof buffer);
    if (len <= 0) {
	fprintf(stderr, "no reply to update?\n");
	goto fail;
    }
    dns_msg_setbuf(msg, buffer, len);

    if (verbose > 2) {
	dumpmsg(msg);
	fprintf(stderr, "\n");
    }

    dns_rd_header(msg, &rheader);
    if (rheader.id != header.id || rheader.opcode != DNS_OP_UPDATE) {
	fprintf(stderr, "bad reply to update request\n");
	goto fail;
    }
    if (verbose > 1)
	fprintf(stderr, "server response: %s\n",
	    dns_rcode_name(rheader.rcode));
    if (rheader.rcode != DNS_NOERROR) {
	rcode = rheader.rcode;
	goto fail;
    }

#if 0					/* XXX always GSS_S_BAD_MIC? */
    /* Verify response */
    if (vctx) {
	dns_msg_setbuf(msg, buffer, len);
	dns_tsig_verify(msg, verify, vctx);
	if (verbose > 1 || (verbose && rheader.rcode))
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
	const char *server, const char *fqdn, const char *server_spn,
	uint16_t utype, uint16_t uclass, uint32_t uttl,
	const void *udata, size_t udatalen, const char *auth_domain)
{
    char buffer[32768];
    struct dns_rr rr, question;
    struct dns_header header;
    int bufferlen;
    int rcode = -1;

    char key_name[DNS_MAXNAME];
    char server_principal[2048];
    gss_ctx_id_t gssctx;
    gss_buffer_desc intok, outtok;
    OM_uint32 major, minor;
    struct dns_tkey tkey;
    struct verify_context vctx;

    make_key_name(fqdn, key_name, sizeof key_name);

    /* The domain server's principal name */
    if (!server_spn) {
       krb5_context krb5_ctx;
       char **realms;

       /* Workaround for vas_gss which uses the default realm instead
	* of detecting the host realm for a service */
       if (vas_krb5_get_context(ctx, &krb5_ctx)) {
	   warnx("vas_krb5_get_context: %s", vas_err_get_string(ctx, 1));
	   goto fail;
       }
       if (krb5_get_host_realm(krb5_ctx, server, &realms)) {
	   warnx("krb5_get_host_realm: %s", krb5_get_error_string(krb5_ctx));
	   goto fail;
       }
       snprintf(server_principal, sizeof server_principal,
	    "dns/%s@%s", server, realms[0]);
       (void)krb5_free_host_realm(krb5_ctx, realms);
       server_spn = server_principal;
    }

    if (verbose)
	fprintf(stderr, "target service: %s\n", server_spn);

    /* Perform the GSS rounds */
    gssctx = GSS_C_NO_CONTEXT;
    intok.length = 0;
    intok.value = NULL;
    outtok.length = 0;
    outtok.value = NULL;
    for (;;) {
	major = vas_gss_spnego_initiate(ctx, id, NULL, &gssctx,
		server_spn,
	       	GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG |
		GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG,
		VAS_GSS_SPNEGO_ENCODING_DER, intok.length ? &intok : NULL,
		&outtok);
	if (GSS_ERROR(major)) {
	    warnx("vas_gss_spnego_initiate: %s", vas_err_get_string(ctx, 1));
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

	    if (verbose)
		fprintf(stderr, "sending tkey query\n");
	    bufferlen = dnstcp_sendmsg(s, msg);
	    if (bufferlen == -1)
		goto fail;

	    if (verbose > 1) {
		dumpmsg(msg);
		fprintf(stderr, "\n");
	    }

	    dns_msg_free(msg);
	    (void)gss_release_buffer(&minor, &outtok);
	} else {
	    if (verbose > 1)
		fprintf(stderr, "no output token needed after this round\n");
	}

	if (major == GSS_S_CONTINUE_NEEDED) {
	    struct dns_msg *msg = dns_msg_new();
	    struct dns_header recv_header;

	    if (verbose)
		fprintf(stderr, "waiting for tkey reply\n");
	    bufferlen = dnstcp_recv(s, buffer, sizeof buffer);
	    if (bufferlen <= 0)
		goto fail;
	    dns_msg_setbuf(msg, buffer, bufferlen);

	    if (verbose > 1) {
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
    if (verbose)
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
	if (verbose)
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

/* Initialise GSS credentials. Returns true on success */
static int
gss_auth_init(vas_ctx_t **vas_ctx_p, vas_id_t **local_id_p, const char *spn)
{
    vas_ctx_t *vas_ctx = NULL;
    vas_id_t *local_id = NULL;
    vas_err_t error;

    /* Initialise VAS */
    error = vas_ctx_alloc(&vas_ctx);
    if (error != VAS_ERR_SUCCESS) {
	warnx("vas_ctx_alloc");
	goto fail;
    }

    error = vas_id_alloc(vas_ctx, spn, &local_id);
    if (error) {
	warnx("vas_id_alloc: %s", vas_err_get_string(vas_ctx, 1));
	goto fail;
    }

    error = vas_id_establish_cred_keytab(vas_ctx, local_id,
	    VAS_ID_FLAG_USE_MEMORY_CCACHE, NULL);
    if (error) {
	warnx("vas_id_establish_cred_keytab: %s", 
		vas_err_get_string(vas_ctx, 1));
	goto fail;
    }

    error = vas_gss_initialize(vas_ctx, local_id);
    if (error) {
	warnx("vas_gss_initialize: %s", 
		vas_err_get_string(vas_ctx, 1));
	goto fail;
    }

    *vas_ctx_p = vas_ctx;
    *local_id_p = local_id;
    return 1;
fail:
    if (vas_ctx)
        vas_ctx_free(vas_ctx);
    return 0;
}

/* Determine the fully qualified domain name of the VAS-joined host */
static int
gss_auth_init_fqdn(vas_ctx_t *vas_ctx, vas_id_t *local_id, char *spn, 
	char **fqdn_p)
{
    vas_computer_t *local_computer;
    char *fqdn = NULL;
    vas_err_t error;

    error = vas_computer_init(vas_ctx, local_id, spn, 
		    VAS_NAME_FLAG_NO_IMPLICIT, &local_computer);
    if (error) {
	warnx("vas_computer_init: %s", vas_err_get_string(vas_ctx, 1));
	return 0;
    }

    error = vas_computer_get_dns_hostname(vas_ctx, local_id, local_computer,
	    &fqdn);
    if (error) {
	warnx("vas_computer_get_dns_hostname: %s",
		vas_err_get_string(vas_ctx, 1));
	return 0;
    }

    *fqdn_p = fqdn;
    return 1;
}

/* Returns the number of dots ('.') in the string s */
static int
count_dots(const char *s)
{
    int ndots = 0;

    while (*s)
	if (*s++ == '.')
	    ndots++;
    return ndots;
}

/* Returns pointer to the parent domain part of a name */
static const char *
parent_domain(const char *d)
{
    for (; *d; d++)
	if (*d == '.') {
	    d++;
	    break;
	}
    return d;
}

/* Load default configuration, once */
static void
config_init_once()
{
    static int config_loaded;

    if (!config_loaded) {
	config_loaded = 1;
	config_load(PATH_SYSCONFDIR "/dnsupdate.conf");
	resconf_init();
    }
}

/* Sets an option of the form "KEY=VALUE" */
static int
config_opt(char *arg)
{
    char *eq;
   
    eq = strchr(arg, '=');
    if (!eq) 
	return 0;
    *eq++ = '\0';
    config_add(arg, eq);
    return 1;
}

int
main(int argc, char **argv)
{
    int ns, s;
    char **server_list = NULL, *server, **serverp;
    char **user_servers = NULL, **host_nameservers;
    vas_ctx_t *vas_ctx = NULL;
    vas_err_t error;
    char *server_spn = NULL;
    char *hostname = NULL;
    char *client_spn = "host/";
    int ret;
    vas_id_t *local_id;
    unsigned char ipaddr[4];
    unsigned int ttl;
    int ch;
    int opterror = 0;
    int security_level;
    int register_reverse;
    int a_registered = 0;
    int updating_ptr, secure, extend_servers_on_fail = 0;
    uint16_t utype;
    const void *udata;
    const char *name;
    char auth_primary[DNS_MAXNAME];
    char auth_domainbuf[DNS_MAXNAME];
    char *user_auth_domain = NULL;
    char *auth_domain;
    size_t udatalen;
    char reverse[4 * 4 + sizeof "IN-ADDR.ARPA"];
    char **domain_list;
    char **ns_list;

    err_enable_syslog(1);

    /* Argument processing */
    while ((ch = getopt(argc, argv, "a:C:d:h:INo:rs:S:t:vV")) != -1)
	switch (ch) {
	case 'a':
	    user_auth_domain = optarg;
	    break;
	case 'C':
	    client_spn = optarg;
	    break;
	case 'd':
	    warnx("-d has been deprecated");
	    break;
	case 'h':
	    hostname = optarg;
	    break;
	case 'I':
	    tsig_name = GSS_TSIG;
            ietf_compliant = 1;
	    break;
	case 'N':
	    config_init_once();
	    config_add("UpdateSecurityLevel", STR(SECURITY_ONLY_UNSECURE));
	    break;
	case 'o':
	    config_init_once();
	    if (!config_opt(optarg)) {
		fprintf(stderr, "bad option '%s'\n", optarg);
		opterror = 1;
	    }
	    break;
	case 'r':
	    config_init_once();
	    config_add("RegisterReverseLookup", "1");
	    break;
	case 's':
	    list_free(user_servers);
	    user_servers = list_from_string(optarg);
	    break;
	case 'S':
	    server_spn = optarg;
	    break;
	case 't':
	    config_init_once();
	    config_add("RegistrationTtl", optarg);
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
	    printf("%s\n", PACKAGE_STRING);
	    exit(0);
	    break;
	default:
	    opterror = 1;
	    break;
	}

    config_init_once();

    /* Expect an IP address argument */
    if (!(optind < argc && my_inet_aton(argv[optind++], ipaddr, sizeof ipaddr)))
	opterror = 1;

    /* Expect no more arguments */
    if (optind != argc)
	opterror = 1;

    if (verbose > 1) {
	int i;
	fprintf(stderr, "command line:");
	for (i = 0; i < argc; i++)
	    fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
    }

    if (opterror) {
	fprintf(stderr, "usage: %s"
			" [-a auth-domain]"
			" [-C client-spn]"
			" [-h hostname]"
			" [-I]"
			" [-N]"
			" [-o option=value]"
			" [-r]"
			" [-s nameserver]"
			" [-S server-spn]"
		        " [-t ttl]"
	       		" [-v]"
	       		" [-V]"
			" ipaddr\n", argv[0]);
	exit(2);
    }

    if (verbose) {
	fprintf(stderr, "dnsupdate %s\n", PACKAGE_VERSION);
	fprintf(stderr, "libvas %s\n", vas_product_version(0, 0, 0));
    }

    if (verbose > 1) { 
	void vas_log_init(int, int, int, void *, int);
	vas_log_init(3, 9, 3, 0, 0);
    }

    /*
     * Sanity check the options 
     */
    ttl = config_get_int("RegistrationTtl", DEFAULT_TTL);
    if (verbose)
	fprintf(stderr, "ttl: %u\n", ttl);

    security_level = config_get_int("UpdateSecurityLevel", 
	    SECURITY_UNSECURE_THEN_SECURE);
    switch (security_level) {
	case SECURITY_ONLY_SECURE:
	case SECURITY_ONLY_UNSECURE:
	case SECURITY_UNSECURE_THEN_SECURE:
	    break;
	default:
	    warnx("Unknown UpdateSecurityLevel %d, using %d\n", security_level,
		    SECURITY_ONLY_SECURE);
	    security_level = SECURITY_ONLY_SECURE;
    }
    if (verbose)
	fprintf(stderr, "security_level: %d\n", security_level);

    register_reverse = config_get_int("RegisterReverseLookup", 
	    REGISTER_PTR_ONLY_IF_A_SUCCEEDS);
    switch (register_reverse) {
	case REGISTER_PTR_NEVER:
	case REGISTER_PTR_ALWAYS:
	case REGISTER_PTR_ONLY_IF_A_SUCCEEDS:
	    break;
	default:
	    warnx("Bad RegisterReverseLookup %d, using %d", register_reverse,
		    REGISTER_PTR_ONLY_IF_A_SUCCEEDS);
	    register_reverse = REGISTER_PTR_ONLY_IF_A_SUCCEEDS;
    }
    if (verbose)
	fprintf(stderr, "register_reverse: %d\n", register_reverse);

    if (verbose) {
	fprintf(stderr, "client_spn: %s\n", client_spn);
	fprintf(stderr, "server_spn: %s\n", server_spn ? server_spn : "(auto)");
	fprintf(stderr, "tsig_name:  %s\n", tsig_name);
	fprintf(stderr, "ipaddr: %u.%u.%u.%u\n", 
		ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    }

    /* Check policy for RegistrationEnabled == 0 */
    if (config_get_int("RegistrationEnabled", 1) == 0) {
	if (verbose)
	    fprintf(stderr, "Dynamic update disabled\n");
	exit(0);
    }

    /* Initialise random number generator */
    init_unique_id();

    /* Try initializing GSS authentication */
    if (security_level == SECURITY_ONLY_UNSECURE)
	vas_ctx = NULL;
    else if (!gss_auth_init(&vas_ctx, &local_id, client_spn)) {
	if (security_level == SECURITY_ONLY_SECURE) 
	    errx(1, "Unable to securely update");
	warnx("Unable to securely update; reverting to unsecure-only");
	vas_ctx = NULL;
	security_level = SECURITY_ONLY_UNSECURE;
    }

    /*
     * STEP 1: Determine the FQDN (hostname) we want to register
     */

    if (vas_ctx && !hostname)
	/* Ask VAS for our fqdn hostname */
	(void)gss_auth_init_fqdn(vas_ctx, local_id, client_spn, &hostname);

    if (!hostname) {
	/* Ask the OS for our FQDN. */
	char local_hostname[DNS_MAXNAME];
	char full_hostname[DNS_MAXNAME];
	struct hostent *host = NULL;

	if (gethostname(local_hostname, sizeof local_hostname) < 0)
	    warn("gethostname");
	else
	    host = gethostbyname(local_hostname);

	if (host && host->h_name) 
	    hostname = host->h_name;
	else
	    hostname = local_hostname;
	
	if (count_dots(hostname) == 0) {
	    if (verbose > 1)
		fprintf(stderr, "hostname %s looks unqualified\n", hostname);
	    if (user_auth_domain) {
		/* Use the user supplied domain from the -a option */
		snprintf(full_hostname, sizeof full_hostname, 
			"%s.%s", hostname, user_auth_domain);
		hostname = full_hostname;
	    } else {
		/* Use the first domain listed in resolv.conf's 
		 * 'domain' or 'search' options */
		domain_list = resconf_get("domain");
		if (!domain_list)
		    domain_list = resconf_get("search");
		if (domain_list && domain_list[0]) {
		    if (verbose)
			fprintf(stderr, "appending domain name %s\n", 
				domain_list[0]);
		    snprintf(full_hostname, sizeof full_hostname, 
			    "%s.%s", hostname, domain_list[0]);
		    hostname = full_hostname;
		}
		resconf_free(domain_list);
	    }
	}
	hostname = strdup(hostname);
    }

    if (!hostname)
        errx(1, "Cannot determine hostname; specify with -h <hostname>");
    if (verbose) 
	fprintf(stderr, "hostname: %s\n", hostname);

    /* This is the reverse IP address we may wish to register */
    snprintf(reverse, sizeof reverse, "%u.%u.%u.%u.IN-ADDR.ARPA",
	    ipaddr[3], ipaddr[2], ipaddr[1], ipaddr[0]);

    /*
     * Connect to the system nameserver
     */
    host_nameservers = resconf_get("nameserver");
    if (!host_nameservers || !*host_nameservers)
	errx(1, "no local nameservers configured");
    ns = -1;
    for (serverp = host_nameservers; *serverp; serverp++) {
	server = *serverp;
	if (verbose)
	    fprintf(stderr, "trying nameserver %s ...\n", server);
	ns = dnstcp_connect(server);
	if (ns != -1) 
	    break;
    }
    if (ns == -1)
	errx(1, "unable to contact system nameserver");
    list_free(host_nameservers);

    /*
     * Loop, first updating the A record, then updating the PTR record
     */
    a_registered = 0;
    for (updating_ptr = 0; updating_ptr <= 1; updating_ptr++) {

	switch (updating_ptr) {
	case 0:
	    /* A record parameters */
	    name = hostname;
	    utype = DNS_TYPE_A;
	    udata = ipaddr;
	    udatalen = sizeof ipaddr;
	    break;
	case 1:
	    /* Logic for whether or not we update PTRs */
	    switch (register_reverse) {
	    case REGISTER_PTR_NEVER:
		continue;
	    case REGISTER_PTR_ONLY_IF_A_SUCCEEDS:
		if (!a_registered)
		    continue;
	    }
	    /* PTR record parameters */
	    name = reverse;
	    utype = DNS_TYPE_PTR;
	    udata = hostname;
	    udatalen = -1;
	    break;
	}

	if (verbose > 1)
	    fprintf(stderr, "starting attempt to register %s %s\n", 
		    utype == DNS_TYPE_A ? "A" : "PTR", name);
	

	/*
	 * Step 2: Figure out which nameserver to update against
	 */

	auth_domain = user_auth_domain;

	/* The user may have supplied a list of nameservers with -n */
	server_list = NULL;
	if (user_servers)
	    server_list = list_dup(user_servers);

	if (list_is_empty_or_null(server_list)) {
	    /* Perform an SOA query on the record name we want to update. 
	     * The primary server from the SOA response becomes the 
	     * first host we will try. */
	    if (query_soa(ns, name, auth_domainbuf, sizeof auth_domainbuf,
			auth_primary, sizeof auth_primary) == 0) 
	    {
		list_free(server_list);
		server_list = list_from_single(auth_primary);
		/* Later we will use auth_domainbuf to find more servers */
		extend_servers_on_fail = 1;
		if (!auth_domain)
		    auth_domain = auth_domainbuf;
	    } else {
		warnx("Cannot find SOA record for %s\n", name);
		extend_servers_on_fail = 0;
	    }
	}

	/* If we still don't have a list of servers, ask VAS for DCs */
	if (vas_ctx && list_is_empty_or_null(server_list)) {
	    char **vas_servers = NULL;
	    error = vas_info_servers(vas_ctx, NULL, NULL, VAS_SRVINFO_TYPE_DC,
		    &vas_servers);
	    if (error)
		warnx("vas_info_servers: %s", vas_err_get_string(vas_ctx, 1));
	    else {
		list_free(server_list);
		server_list = list_dup(vas_servers);
		vas_info_servers_free(vas_ctx, vas_servers);
	    }
	}

	/* Last resort: try all nameservers in resolv.conf */
	if (list_is_empty_or_null(server_list)) {
	    list_free(server_list);
	    server_list = resconf_get("nameserver");
	}

	if (list_is_empty_or_null(server_list)) 
	    errx(1, "Cannot determine nameservers to update against");

	if (!auth_domain) 
	    /* Use the parent domain as a best guess for the auth domain */
	    auth_domain = (char *)parent_domain(name);

	if (verbose)
	    fprintf(stderr, "auth_domain: %s\n", 
		    *auth_domain ? auth_domain : "(root)");

	/* Check for non FQDNs and top-level domain names */
	if (count_dots(auth_domain) < 1) {
	    warnx("auth domain '%.255s' is top-level", auth_domain);
	    if (config_get_int("UpdateTopLevelDomainZones", 0) == 0) {
		if (verbose)
		    warnx("Refusing to update top level domain zones\n");
		continue;
	    }
	}

	/*
	 * STEP 3: Try sending UPDATE requests to each of the servers
	 * in the server_list until something works.
	 */

	ret = -1;
	ns_list = NULL;
	for (serverp = server_list; ; serverp++) {
	    if (!*serverp && extend_servers_on_fail) {
		char **lp;
		/* If we exhausted the server list obtained from an SOA query
		 * then try adding more by performing an NS query on 
		 * the authoritative domain itself */
		extend_servers_on_fail = 0;
		if (verbose)
		    fprintf(stderr, "querying NS for %s\n", auth_domainbuf);
		if (query_ns(ns, auth_domainbuf, &ns_list) != 0)
		    warnx("unable to get NS records for %s", auth_domainbuf);
		for (lp = server_list; *lp; lp++)
		    list_remove(ns_list, *lp);
		serverp = ns_list;
	    }
	    if (!serverp || !*serverp) {
		if (verbose)
		    fprintf(stderr, "out of servers to try\n");
		break;
	    }

	    /* Connect to our next candidate nameserver */
	    server = *serverp;
	    if (verbose)
		fprintf(stderr, "trying nameserver %s...\n", server);
	    s = dnstcp_connect(server);
	    if (s == -1)
		continue;

	    /*
	     * Loop for connecting unsecurely, then securely.
	     * secure==0 --> Insecure update attempt
	     * secure==1 --> Secure (GSSAPI) update attempt
	     */
	    for (secure = 0; secure <= 1; secure++) {

		if (security_level == SECURITY_ONLY_SECURE && !secure)
		    continue;
		if (security_level == SECURITY_ONLY_UNSECURE && secure)
		    continue;

		if (verbose)
		    fprintf(stderr, "attempting %s update %s %s\n", 
			    secure ? "secure" : "unsecure",
			    name,
			    utype == DNS_TYPE_A ? "A" : "PTR");

		if (secure) {
		    ret = gss_update(vas_ctx, local_id, s, server, name, 
			    server_spn, utype, DNS_CLASS_IN, ttl, udata, 
			    udatalen, auth_domain);
		} else {
		    ret = update(s, NULL, name, utype, DNS_CLASS_IN,
			    ttl, udata, udatalen, auth_domain);
		}
		if (ret == 0) { /* Success! */
		    /* Remember that we updated the A record */
		    if (!updating_ptr)
			a_registered = 1;
		    /* Break out of the secure loop when done */
		    break;
		} 
		if (ret > 0 && (verbose ||
			 security_level == SECURITY_ONLY_UNSECURE || secure))
		    fprintf(stderr, "%s %s update %s: %s\n", server,
			    secure ? "secure" : "unsecure",
			    utype == DNS_TYPE_A ? "A" : "PTR",
			    dns_rcode_name(ret));
	    }
	    dnstcp_close(&s);

	    if (ret == 0)
		/* Break out of the server list after a success */
		break;
	}
	if (verbose)
	    fprintf(stderr, "update of %s %s %s\n",
		    name, 
		    utype == DNS_TYPE_A ? "A" : "PTR",
		    (ret == 0) ? "succeeded" : "failed");
	list_free(ns_list);
    }
    list_free(server_list);

    dnstcp_close(&ns);

    if (vas_ctx)
        vas_ctx_free(vas_ctx);

    /* Exit true if we registered the A address */
    exit(a_registered ? 0 : 1);
}
