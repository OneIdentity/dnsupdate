#ifndef dns_debug_h
#define dns_debug_h

/* Prints memory in hex format */
void dumphex(const void *buf, size_t len);
/* Prints a DNS RR entry (excluding the data section) */
void dumprr(const struct dns_rr *rr, const char *name);
/* Prints content of an DNS message (advances message pointer) */
void dumpmsg(struct dns_msg *msg);
/* Returns a human-readable DNS record type string. */
const char *dns_type_str(uint16_t type);

extern int dumpdebug;

#endif
