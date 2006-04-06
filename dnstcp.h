#ifndef dns_tcp_h
#define dns_tcp_h

int dnstcp_connect(const char *host);
int dnstcp_send(int s, const void *buf, size_t len);
int dnstcp_recv(int s, void *buf, size_t bufsz);
int dnstcp_sendmsg(int s, const struct dns_msg *msg);
int dnstcp_recvmsg(int s, void *buf, size_t bufsz, struct dns_msg *msg);
void dnstcp_close(int *s);

#endif
