#ifndef dns_tsig_h
#define dns_tsig_h

struct dns_tsig_time {
    uint16_t	hi;
    uint32_t	lo;
};

struct dns_tsig {
    char	 algorithm[256];
    struct dns_tsig_time time;
    uint16_t	 fudge;
    uint16_t	 maclen;
    void	*mac;
    uint16_t	 orig_id;
    uint16_t	 error;
    uint16_t	 otherlen;
    void	*other;
};

void dns_tsig_wr(struct dns_msg *msg, const struct dns_tsig *tsig);
void dns_tsig_rd(struct dns_msg *msg, struct dns_tsig *tsig);

void dns_tsig_wr_time(struct dns_msg *msg, const struct dns_tsig_time *time);
void dns_tsig_rd_time(struct dns_msg *msg, struct dns_tsig_time *time);

void dns_tsig_wr_variables(struct dns_msg *varmsg, struct dns_rr *rr,
	        struct dns_tsig *tsig);

void dns_tsig_verify(struct dns_msg *msg,
       	int (*verifyfn)(const void *buf, size_t buflen, const char *key_name, 
	    	        const struct dns_tsig *tsig, void *context),
       	void *context);

void dns_tsig_sign(struct dns_msg *msg, const char *key_name,
	const char *algorithm, uint16_t fudge, void *other, size_t otherlen,
	void * (*sign)(struct dns_tsig *tsig, void *data, size_t datalen, 
	    	       void *context),
	void *context);

void dns_tsig_set_algorithm(struct dns_tsig *tsig, const char *algorithm);


#endif
