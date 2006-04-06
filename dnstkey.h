#ifndef dns_tkey_h
#define dns_tkey_h

struct dns_tkey {
	char                algorithm[256];
	uint32_t            inception;
	uint32_t            expiration;
	uint16_t            mode;
	uint16_t            error;
	uint16_t            keysz;
	void               *key;
	uint16_t            othersz;
	void               *other;
};

#define DNS_TKEY_MODE_GSSAPI	3

void dns_tkey_wr(struct dns_msg *msg, const struct dns_tkey *tkey);
void dns_tkey_rd(struct dns_msg *msg, struct dns_tkey *tkey);

#endif
