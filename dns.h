#ifndef dns_h_
#define dns_h_

#include <inttypes.h>

/*
 * A collection of functions to construct and parse DNS packets.
 * Most functions deal with a 'dns_msg' structure, which is
 * just a growable octet buffer with a name compression table.
 *
 * The 'dns_header' and 'dns_rr' structures are provided for
 * convenience; there are functions to read and write them in/out of
 * the dns_msg.
 */

/* RFC1035 header */
struct dns_header {
     uint16_t	id;
     uint16_t	response	:1,	/* response == !query */
	 	opcode		:4,
		authoritative	:1,
		truncated	:1,
		recurse_desired	:1,
		recurse_avail	:1,
		z		:3,
		rcode		:4;
     uint16_t	qdcount, ancount, nscount, arcount;
};

/* opcode */
#define DNS_OP_QUERY	0	/* query */
#define DNS_OP_IQUERY	1	/* inverse query */
#define DNS_OP_STATUS	2	/* status request */
#define DNS_OP_UPDATE	5	/* update request */

/* rcode */
#define	DNS_NOERROR	0	/* no error */
#define	DNS_FORMERR	1	/* format error */
#define	DNS_SERVFAIL	2	/* server failure */
#define	DNS_NXDOMAIN	3	/* name error */
#define	DNS_NOTIMP	4	/* not implemented */
#define	DNS_REFUSED	5	/* refused */
#define	DNS_YXDOMAIN	6	/* unwanted domain exists */
#define	DNS_YXRRSET	7	/* unwanted RRs exist */
#define	DNS_NXRRSET 	8	/* wanted RRs don't exist */
#define	DNS_NOTAUTH	9	/* not authorized */
#define	DNS_NOTZONE	10	/* not a zone */
#define	DNS_BADSIG	16	/* bad signature */
#define	DNS_BADKEY 	17	/* bad key */
#define	DNS_BADTIME 	18	/* bad time */
#define	DNS_BADMODE 	19	/* bad mode */
#define	DNS_BADNAME 	20	/* bad name */
#define	DNS_BADALG 	21	/* bad algorithm */

#define DNS_MAXNAME	256	/* max size of an uncompressed domain name */
				/* string including nul (HOST_NAME_MAX+1) */

/* A resource record head */
struct dns_rr {
     char 	name[DNS_MAXNAME];	/* uncompressed */
     uint16_t	type;
     uint16_t	class_;
     int32_t	ttl;		/* not present in questions */
     /* All RR heads are followed by a 16-bit data length then the data */
};

#define DNS_TYPE_A	1
#define DNS_TYPE_NS	2
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_NULL	10
#define DNS_TYPE_PTR	12
#define DNS_TYPE_TXT	16
#define DNS_TYPE_TKEY	249
#define DNS_TYPE_TSIG	250
#define DNS_TYPE_ANY	255	/* only valid in queries/matching */

#define DNS_CLASS_IN	1
#define DNS_CLASS_ANY	255

/* A read/write message structure */
struct dns_msg {
    uint16_t	pos;
    void	*data;		/* caller manages this buffer */
    uint16_t	remain[4];
    uint16_t	depth;
    struct {
	char name[DNS_MAXNAME];
	uint16_t offset;
    } namecache[255];
    unsigned char namecachelen;
};

/* Stores a name in an RR */
void dns_rr_set_name(struct dns_rr *rr, const char *name);

/* Creates a new message structure for reading/writing */
struct dns_msg *dns_msg_new(void);
/*
 * Sets the read/write buffer storage to use, and resets position to zero.
 * Caller still owns the buffer memory.
 */
void dns_msg_setbuf(struct dns_msg *, void *, size_t);

/* Returns the current position in the read/write buffer */
size_t dns_msg_getpos(const struct dns_msg *msg);

/* Returns the data remaining in a read buffer */
void dns_msg_getbuf(const struct dns_msg *msg, void **bufp, size_t *szp);


/* Releases storage associated with the message (but not the data field) */
void   dns_msg_free(struct dns_msg *msg);

/* Reads a header structure from the buffer */
void   dns_rd_header(struct dns_msg *msg, struct dns_header *header);
/* Skips the given number of bytes in the message */
void   dns_rd_skip(struct dns_msg *msg, uint16_t len);
/* Reads a domain name from the buffer and stores as a dot-delimited string */
void   dns_rd_name(struct dns_msg *msg, char *buf, size_t bufsz);
/* Reads a canonical-only domain name from the buffer and stores */
void   dns_rd_name_canon(struct dns_msg *msg, char *buf, size_t bufsz);
/* Reads binary data into the buffer */
void   dns_rd_data_raw(struct dns_msg *msg, void *buf, uint16_t len);
/* Reads a uint16_t followed by binary data into a buffer */
uint16_t dns_rd_data(struct dns_msg *msg, void *buf, size_t bufsz);
/* Reads a uint16_t, stores pointer into msg buffer and skips the data */
uint16_t dns_rd_datap(struct dns_msg *msg, void **ptr);
/* Reads an unsigned 16-bit integer */
uint16_t dns_rd_uint16(struct dns_msg *msg);
/* Reads an unsigned 32-bit integer */
uint32_t dns_rd_uint32(struct dns_msg *msg);
/* Reads a signed 32-bit integer */
int32_t  dns_rd_int32(struct dns_msg *msg);
/* Reads a resource record structure, EXCLUDING rdata */
void   dns_rd_rr_head(struct dns_msg *msg, struct dns_rr *rr);
/* Reads a question (i.e. an rr without the ttl) */
void   dns_rd_question(struct dns_msg *msg, struct dns_rr *question);

/* 
 * The error handler is called when a bounds is exceeded by dns_rd_*
 * dns_rd_begin and _end indicate change the bounds so that
 * elements can be read from an opaque data blob. _end will skip to
 * the end of the blob and emit a warning message if not already there.
 *
 * dns_rd_begin reads a uint16_t.
 */
void   dns_set_error_handler(void (*fn)(const char *, void *), void *);

/* Reads a uint16_t and then pushes a new error boundary */
void   dns_rd_begin(struct dns_msg *msg);
/* Pushes a new error boundary */
void   dns_rd_begin_raw(struct dns_msg *msg, uint16_t);
/* Skips to the end of the current boundary and pops the boundary stack */
void   dns_rd_end(struct dns_msg *msg);
/* Returns the number of bytes remaining until a boundary will be hit */
uint16_t dns_rd_remain(const struct dns_msg *msg);

/* Writes the header structure */
void   dns_wr_header(struct dns_msg *msg, const struct dns_header *header);
/* Writes a dot-delimited name as a sequence of labels */
void   dns_wr_name(struct dns_msg *msg, const char *name);
/* Writes a dot-delimited name as a sequence of uncompressed labels */
void   dns_wr_name_canon(struct dns_msg *msg, const char *name);
/* Writes a uint16_t followed by binary data */
void   dns_wr_data(struct dns_msg *msg, const void *buf, uint16_t len);
/* Writes raw binary data */
void   dns_wr_data_raw(struct dns_msg *msg, const void *buf, size_t len);
/* Writes an unsigned 16-bit integer */
void   dns_wr_uint16(struct dns_msg *msg, uint16_t val);
/* Writes an unsigned 32-bit integer */
void   dns_wr_uint32(struct dns_msg *msg, uint32_t val);
/* Writes a signed 32-bit integer */
void   dns_wr_int32(struct dns_msg *msg, int32_t val);
/* Writes a resource record structure */
void   dns_wr_rr_head(struct dns_msg *msg, const struct dns_rr *rr);
/* Writes a question (i.e. an rr without the ttl) */
void   dns_wr_question(struct dns_msg *msg, const struct dns_rr *question);

/* Makes space for a uint16_t, stores its offset into mark */
void   dns_wr_begin(struct dns_msg *msg, uint16_t *mark);
/* Updates the offset size since the last dns_wr_begin() */
void   dns_wr_end(struct dns_msg *msg, uint16_t *mark);

/* Converts a write buffer ito a read buffer, and rewinds */
void   dns_wr_finish(struct dns_msg *msg);

/* Convenience function to increment the additional record count */
void   dns_wr_inc_arcount(struct dns_msg *msg);
/* Convenience function to decrement the additional record count */
void   dns_rd_dec_arcount(struct dns_msg *msg);
/* Convenience function to increment the answer record count */
void   dns_wr_inc_ancount(struct dns_msg *msg);
/* Convenience function to increment the authoritative ns record count */
void   dns_wr_inc_nscount(struct dns_msg *msg);

/* Returns an error code as a string */
const char *dns_rcode_name(uint16_t rcode);

extern int dns_never_compress;

#endif
