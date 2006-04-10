#include <err.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vas.h>
#include <vas_gss.h>
#include "dns.h"
#include "dnsdebug.h"
#include "dnstcp.h"
#include "dnstkey.h"
#include "dnstsig.h"

/*
 * Testing the dynamic DNS update protocol
 */

#define GSS_MICROSOFT_COM	"gss.microsoft.com"
#define GSS_TSIG		"gss-tsig"

static uint16_t next_id = 1;
int vflag;

/* Returns a unique message ID for this session */
static uint16_t
unique_id()
{
    return next_id++;
}

/* Initialises the unique ID stream */
void
init_unique_id()
{
    srandom(time(0) * getpid());
    next_id = random();
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
#if 1
    buf[i] = 0;
#else
    /* Problem with compression somewhere? */
    snprintf(buf + 31, bufsz- 31, ".%s", fqdn);
#endif
    if (vflag)
	fprintf(stderr, "using TKEY %s\n", buf);
}

struct verify_context {
    gss_ctx_id_t gssctx;
    const char *key_name;
};

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
	fprintf(stderr, "gss_verify_mic: failed! major=0x%x\n", major);
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
    if (GSS_ERROR(major))
	errx(1, "gss_get_mic: failed! major=0x%x", major);

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
 * Perform a DNS update
 * Returns 0 on error.
 */
static int
update(int s, struct verify_context *vctx, 
	const char *fqdn, uint16_t utype, uint16_t uclass, 
	uint32_t uttl, const void *udata, size_t udatalen)
{
    struct dns_msg *msg;
    struct dns_header header, rheader;
    struct dns_rr zonerr, prerr, delrr, addrr;
    char buffer[32768];
    const char *domain;
    int len;

    /* Obtain the domain of fqdn */
    for (domain = fqdn; *domain; domain++)
	if (*domain == '.') { domain++; break; }
    if (!*domain) {
	fprintf(stderr, "no domain? %s\n", fqdn);
       	return 0;
    }

    memset(&header, 0, sizeof header);
    header.id = unique_id();
    header.opcode = DNS_OP_UPDATE;

    /* Zones/Questions */
    header.qdcount++;
    memset(&zonerr, 0, sizeof zonerr);
    dns_rr_set_name(&zonerr, domain);
    zonerr.type = DNS_TYPE_SOA;
    zonerr.class_ = DNS_CLASS_IN;

    /* Prerequisites/Answers */
    header.ancount++;
    memset(&prerr, 0, sizeof prerr);
    dns_rr_set_name(&prerr, domain);
    prerr.type = DNS_TYPE_ANY;
    prerr.class_ = DNS_CLASS_ANY;

    /* Updates/Authoritatives */
    header.nscount++;
    memset(&delrr, 0, sizeof delrr);
    dns_rr_set_name(&delrr, fqdn);
    delrr.type = utype;
    delrr.class_ = DNS_CLASS_ANY;

    header.nscount++;
    memset(&addrr, 0, sizeof addrr);
    dns_rr_set_name(&addrr, fqdn);
    addrr.type = utype;
    addrr.class_ = uclass;
    addrr.ttl = uttl;

    msg = dns_msg_new();
    dns_msg_setbuf(msg, buffer, sizeof buffer);
    dns_wr_header(msg, &header);
    dns_wr_question(msg, &zonerr);
    dns_wr_rr_head(msg, &prerr);
    dns_wr_data(msg, NULL, 0);
    dns_wr_rr_head(msg, &delrr);
    dns_wr_data(msg, NULL, 0);
    dns_wr_rr_head(msg, &addrr);
    dns_wr_data(msg, udata, udatalen);

    if (vctx)
	dns_tsig_sign(msg, vctx->key_name, GSS_MICROSOFT_COM, 36000, NULL, 0,
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
	goto fail;
    }

    /* TODO: verify the packet TSIG */

    dns_msg_free(msg);
    return 1;
fail:
    dns_msg_free(msg);
    return 0;
}

/* 
 * Negotiate a GSS TKEY, and then call update()
 * Returns 0 on failure
 */
static int
gss_update(vas_ctx_t *ctx, vas_id_t *id, int s,
	const char *server, const char *fqdn, const char *domain,
	uint16_t utype, uint16_t uclass, uint32_t uttl,
	const void *udata, size_t udatalen)
{
    char buffer[32768];
    struct dns_rr rr, question;
    struct dns_header header;
    int bufferlen;

    char key_name[256];
    char server_principal[2048];
    gss_ctx_id_t gssctx;
    gss_buffer_desc intok, outtok;
    OM_uint32 major, minor;
    struct dns_tkey tkey;
    struct verify_context vctx;

    make_key_name(fqdn, key_name, sizeof key_name);

    /* The domain server's principal name */
    snprintf(server_principal, sizeof server_principal,
	    "dns/%s@%s", server, domain);
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
		    GSS_MICROSOFT_COM);
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
		fprintf(stderr, "sending:\n");
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
	    if (vflag)
		fprintf(stderr, "no output token needed after this round\n");
	}

	if (major == GSS_S_CONTINUE_NEEDED) {
	    struct dns_msg *msg = dns_msg_new();
	    struct dns_header recv_header;

	    if (vflag)
		fprintf(stderr, "waiting for reply\n");
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
	    assert(name_eq(tkey.algorithm, GSS_MICROSOFT_COM));
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
	fprintf(stderr, "warning: final TSIG from server was not signed\n");

    return update(s, &vctx, fqdn, utype, uclass, uttl, udata, udatalen);

fail:
    return 0;
}

static int
aton(const char *s, unsigned char *ipaddr)
{
    unsigned int octet[4];
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
    vas_ctx_t *vas_ctx;
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

    while ((ch = getopt(argc, argv, "d:h:s:t:v")) != -1)
	switch (ch) {
	case 'd':
	    domain = optarg;
	    break;
	case 'h':
	    fqdn = optarg;
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

    if (!(optind < argc && aton(argv[optind++], ipaddr)))
	opterror = 1;

    if (optind != argc)
	opterror = 1;

    if (opterror) {
	fprintf(stderr, "usage: %s"
			" [-d domain]"
			" [-h hostname]"
			" [-s nameserver]"
		        " [-t ttl]"
	       		" [-v]"
			" ipaddr\n", argv[0]);
	exit(2);
    }

    if (vflag) {
	fprintf(stderr, "spn: %s\n", spn);
	fprintf(stderr, "ttl: %u\n", ttl);
	fprintf(stderr, "ipaddr: %u.%u.%u.%u\n", 
		ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    }

    /* Initialise random number generator */
    init_unique_id();

    /* Enable VAS debugging */
    { extern void vas_log_init(int,int,int,const char *,int);
      vas_log_init(4,5,5,NULL,0); }

    /* Obtain a VAS context */
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
	if (vflag)
	    fprintf(stderr, "hostname: %s\n", fqdn);
    }

    if (!domain) {
	error = vas_info_joined_domain(vas_ctx, &domain, NULL);
	if (error)
	    errx(1, "vas_info_joined_domain: %s", 
		    vas_err_get_string(vas_ctx, 1));
    }
    if (vflag)
	fprintf(stderr, "domain: %s\n", domain);

    if (nameserver) {
	user_servers[0] = nameserver;
	user_servers[1] = NULL;
	servers = user_servers;
    } else {
	/* Connect to a server */
	error = vas_info_servers(vas_ctx, NULL, NULL, VAS_SRVINFO_TYPE_DC,
		&servers);
	if (error)
	    errx(1, "vas_info_servers: %s", vas_err_get_string(vas_ctx, 1));
    }

    /* Contact each known server, until one works */
    ret = 0;
    for (serverp = servers; *serverp; serverp++) {
	if (vflag)
	    fprintf(stderr, "trying %s...\n", *serverp);
	s = dnstcp_connect(*serverp);
	if (s != -1) {
	    ret = gss_update(vas_ctx, local_id, s, *serverp, fqdn, domain,
		    DNS_TYPE_A, DNS_CLASS_IN, ttl, ipaddr, sizeof ipaddr);
	    dnstcp_close(&s);
	    if (ret)
		break;
	}
    }

    free(domain);
    if (!nameserver)
	vas_info_servers_free(vas_ctx, servers);
    vas_ctx_free(vas_ctx);

    exit(ret ? 0 : 1);
}
