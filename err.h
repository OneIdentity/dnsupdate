#ifndef err_h_
#define err_h_

/* Avoid conflicting with libc implementations */
#define err   dnsupdate_err
#define errx  dnsupdate_errx
#define warn  dnsupdate_warn
#define warnx dnsupdate_warnx

void err_enable_syslog(int);
void errx(int exitcode, const char *fmt, ...);
void err(int exitcode, const char *fmt, ...);
void warnx(const char *fmt, ...);
void warn(const char *fmt, ...);

#endif
