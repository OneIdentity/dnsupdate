#ifndef err_h_
#define err_h_

void errx(int exitcode, const char *fmt, ...);
void err(int exitcode, const char *fmt, ...);
void warnx(const char *fmt, ...);
void warn(const char *fmt, ...);

#endif
