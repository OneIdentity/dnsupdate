/* (c) 2006 Quest Software, Inc. All rights reserved. */
/* David Leonard, 2006 */

#include "common.h"
#include "dns.h"
#include "dnstkey.h"

/*
 * TKEY (transaction key) records are described in RFC2930.
 */

void
dns_tkey_wr(struct dns_msg *msg, const struct dns_tkey *tkey)
{
    uint16_t mark;
    dns_wr_begin(msg, &mark);
    dns_wr_name(msg, tkey->algorithm);
    dns_wr_uint32(msg, tkey->inception);
    dns_wr_uint32(msg, tkey->expiration);
    dns_wr_uint16(msg, tkey->mode);
    dns_wr_uint16(msg, tkey->error);
    dns_wr_data(msg, tkey->key, tkey->keysz);
    dns_wr_data(msg, tkey->other, tkey->othersz);
    dns_wr_end(msg, &mark);
}

void
dns_tkey_rd(struct dns_msg *msg, struct dns_tkey *tkey)
{
    dns_rd_begin(msg);
    dns_rd_name(msg, tkey->algorithm, sizeof tkey->algorithm);
    tkey->inception = dns_rd_uint32(msg);
    tkey->expiration = dns_rd_uint32(msg);
    tkey->mode = dns_rd_uint16(msg);
    tkey->error = dns_rd_uint16(msg);
    tkey->keysz = dns_rd_datap(msg, &tkey->key);
    tkey->othersz = dns_rd_datap(msg, &tkey->other);
    dns_rd_end(msg);
}

