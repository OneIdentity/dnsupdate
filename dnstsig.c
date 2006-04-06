/* (c) 2006, Quest Software, Inc. All rights reserved. */
/* David Leonard, 2006 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <err.h>
#include "dns.h"
#include "dnstsig.h"

/*
 * DNS TSIG is described in RFC 2845.
 * Generally, a DNS packet is formed, and signed by adding an
 * extract resource record to the end. The signature is checked
 * by removing the record and recomputing/checking the signature.
 * Some extra mayhem is required to tack on TSIG 'variables' which
 * act to bind the packet to a time context.
 */

void
dns_tsig_set_algorithm(struct dns_tsig *tsig, const char *algorithm)
{
    snprintf(tsig->algorithm, sizeof tsig->algorithm, "%s", algorithm);
}

/* Writes a TSIG time into a message buffer */
void
dns_tsig_wr_time(struct dns_msg *msg, const struct dns_tsig_time *time)
{
    dns_wr_uint16(msg, time->hi);
    dns_wr_uint32(msg, time->lo);
}

/* Reads a TSIG time out of a message buffer */
void
dns_tsig_rd_time(struct dns_msg *msg, struct dns_tsig_time *time)
{
    time->hi = dns_rd_uint16(msg);
    time->lo = dns_rd_uint32(msg);
}

/* Writes the RDATA portion of a TSIG RR */
void
dns_tsig_wr(struct dns_msg *msg, const struct dns_tsig *tsig)
{
    uint16_t mark;
    dns_wr_begin(msg, &mark);
    dns_wr_name(msg, tsig->algorithm);
    dns_tsig_wr_time(msg, &tsig->time);
    dns_wr_uint16(msg, tsig->fudge);
    dns_wr_data(msg, tsig->mac, tsig->maclen);
    dns_wr_uint16(msg, tsig->orig_id);
    dns_wr_uint16(msg, tsig->error);
    dns_wr_data(msg, tsig->other, tsig->otherlen);
    dns_wr_end(msg, &mark);
}

/* Reads the RDATA portion of a TSIG RR */
void
dns_tsig_rd(struct dns_msg *msg, struct dns_tsig *tsig)
{
    dns_rd_begin(msg);
    dns_rd_name(msg, tsig->algorithm, sizeof tsig->algorithm);
    dns_tsig_rd_time(msg, &tsig->time);
    tsig->fudge = dns_rd_uint16(msg);
    tsig->maclen = dns_rd_datap(msg, &tsig->mac);
    tsig->orig_id = dns_rd_uint16(msg);
    tsig->error = dns_rd_uint16(msg);
    tsig->otherlen = dns_rd_datap(msg, &tsig->other);
    dns_rd_end(msg);
}

/* 
 * Builds and writes a TSIG variables block to a message buffer.
 * The written data is never sent on the wire and is only used
 * internally for the message hashing
 **/
void
dns_tsig_wr_variables(struct dns_msg *varmsg, struct dns_rr *rr, 
	struct dns_tsig *tsig)
{
    dns_wr_name_canon(varmsg, rr->name);
    dns_wr_uint16(varmsg, rr->class_);
    dns_wr_uint32(varmsg, rr->ttl);
    dns_wr_name_canon(varmsg, tsig->algorithm);
    dns_tsig_wr_time(varmsg, &tsig->time);
    dns_wr_uint16(varmsg, tsig->fudge);
    dns_wr_uint16(varmsg, tsig->error);
    dns_wr_data(varmsg, tsig->other, tsig->otherlen);
}

/*
 * Seeks through a readable DNS message for the final TKEY AR,
 * decrements the arcount, and calls the verifyfn
 * expecting it to return 1 for success. On success, removes the
 * TKEY record from the end, and rewinds the msg for reading.
 */
void
dns_tsig_verify(struct dns_msg *msg, 
	int (*verifyfn)(const void *buf, size_t buflen, 
	    		const char *key_name,
	    		const struct dns_tsig *tsig,
			void *context),
	void *context)
{
    struct dns_header header;
    struct dns_tsig tsig;
    struct dns_rr rr;
    uint16_t len, varlen;
    void *data;
    unsigned char *p;
    char varbuf[32768];
    struct dns_msg *varmsg;
    char *maccp, *othercp;
    int verified;

    dns_rd_header(msg, &header);
    if (header.arcount == 0)
	goto fail;
    header.arcount--;

    /* Skip everything */
    while (header.qdcount--)
	dns_rd_question(msg, &rr);
    while (header.ancount--) {
	dns_rd_rr_head(msg, &rr);
	dns_rd_datap(msg, &data);
    }
    while (header.nscount--) {
	dns_rd_rr_head(msg, &rr);
	dns_rd_datap(msg, &data);
    }
    while (header.arcount--) {
	dns_rd_rr_head(msg, &rr);
	dns_rd_datap(msg, &data);
    }

    /* Record the end of the signed message */
    len = dns_msg_getpos(msg);

    dns_rd_rr_head(msg, &rr);
    if (rr.type != DNS_TYPE_TSIG)
	goto fail;
    dns_tsig_rd(msg, &tsig);

    if (tsig.error != DNS_NOERROR)
	goto fail;
    if (tsig.orig_id != header.id)
	goto fail;

    /* Duplicate the mac and other strings since we stomp on the raw data */
    if (tsig.maclen) {
	maccp = malloc(tsig.maclen);
	memcpy(maccp, tsig.mac, tsig.maclen);
    } else
	maccp = NULL;
    tsig.mac = maccp;
    if (tsig.otherlen) {
	othercp = malloc(tsig.otherlen);
	memcpy(othercp, tsig.other, tsig.otherlen);
    } else
	othercp = NULL;
    tsig.other = othercp;
         
    /* Construct the TSIG variables */
    varmsg = dns_msg_new();
    dns_msg_setbuf(varmsg, varbuf, sizeof varbuf);
    dns_tsig_wr_variables(varmsg, &rr, &tsig);
    varlen = dns_msg_getpos(varmsg);
    dns_wr_finish(varmsg);

    /* Overwrite the TSIG record with the TSIG variables block */
    p = (unsigned char *)msg->data;
    memcpy(p + len, varmsg->data, varlen);
    dns_msg_free(varmsg);

    /* Decrement the additional record count */
    dns_rd_dec_arcount(msg); 

    /* Patch the header ID in case it was changed */
    p[0] = (tsig.orig_id >> 8) & 0xff;
    p[1] = tsig.orig_id & 0xff;

    /* Perform the check */
    verified = (*verifyfn)(msg->data, len + varlen, rr.name, &tsig, context);
    if (maccp) free(maccp);
    if (othercp) free(othercp);

    /* Undo the header ID patch */
    p[0] = (header.id >> 8) & 0xff;
    p[1] = header.id & 0xff;

    /* Rewind the message, stripping the TSIG record; AR count remains dec'd */
    dns_msg_setbuf(msg, msg->data, len);

    if (!verified)
	goto fail;

    return;

fail:
    errx(1, "TSIG verification failed");
}

/*
 * Signs a DNS message by appending a TSIG record to it; the additional-record
 * count is incremented by this function.
 * The signing function must set the mac and maclen fields in the
 * tsig structure to something non-empty. If it returns a pointer,
 * that pointer will be freed after the packet is signed. (intended
 * use is for it to store the mic)
 * [XXX the algorithm, fudge and other data should be provided
 *  by the signing function]
 */
void
dns_tsig_sign(struct dns_msg *msg, 
	const char *key_name,
	const char *algorithm,
	uint16_t fudge,
	void *other, size_t otherlen,
	void * (*sign)(struct dns_tsig *tsig,
	    	    void *data, size_t datalen, void *context),
	void *context)
{
    size_t pos;
    struct dns_rr rr;
    struct dns_tsig tsig;
    unsigned char *p;
    void *ptr;

    /* Construct the TKEY RR header */
    dns_rr_set_name(&rr, key_name);
    rr.type = DNS_TYPE_TSIG;
    rr.class_ = DNS_CLASS_ANY;
    rr.ttl = 0;

    /* Construct (most of) the TKEY RR RDATA */
    dns_tsig_set_algorithm(&tsig, algorithm);
    tsig.time.hi = 0;
    tsig.time.lo = time(0);
    tsig.fudge = fudge;
    p = (unsigned char *)msg->data;
    tsig.orig_id = (p[0] << 8) | p[1];
    tsig.error = DNS_NOERROR;
    tsig.maclen = 0;		/* To be set by sign() */
    tsig.mac = NULL;		/* To be set by sign() */
    tsig.otherlen = otherlen;
    tsig.other = other;

    /* Append the raw TKEY variables */
    pos = dns_msg_getpos(msg);
    dns_tsig_wr_variables(msg, &rr, &tsig);
    ptr = (*sign)(&tsig, msg->data, dns_msg_getpos(msg), context);
    assert(tsig.maclen == 0 || tsig.mac != NULL);
    msg->pos = pos;		/* Remove the raw TKEY variables */
    dns_wr_rr_head(msg, &rr);	/* Write the real TKEY record */
    dns_tsig_wr(msg, &tsig);
    dns_wr_inc_arcount(msg);
    if (ptr != NULL) 
	free(ptr);
}
