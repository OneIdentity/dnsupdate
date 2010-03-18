/* (c) 2008, Quest Software Inc. All rights reserved. */
/*
 * Tests the DNS decoder by reading a single packet on stdin
 * and attempting to dumping the output.
 */

#include "common.h"
#include "dns.h"
#include "dnstcp.h"
#include "dnsdebug.h"
#include "err.h"

int verbose;

static int
read_raw(FILE *input, char *inbuf, size_t bufsz)
{
    int inlen = 0;
    int inread;

    while (!feof(input) && !ferror(input)) {
        inread = fread(inbuf + inlen, 1, bufsz - inlen, input);
        inlen += inread;
    }
    return inlen;
}

static int
read_hex(FILE *input, char *inbuf, size_t bufsz)
{
    int inlen = 0;
    int inread;
    enum { sOFFSET, sBYTE1, sBYTE2, sGAP1, sGAP2, sEXTRA } state = sOFFSET;
    unsigned int value;

    // 0200: 00 01 00 00 0e 10 00 0b  08 61 64 30 62 7a 32 63   ........ .ad0bz2c
#   define ishex(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f'))
#   define hexvalue(c) ((c) - ((c) >= 'a' ? 'a' - 10 : '0'))

    value = 0;
    state = sOFFSET;
    while (!feof(input) && !ferror(input)) {
        int ch = getc(input);
        if (ch == -1)
            break;
        if (ishex(ch))
            value = (value << 4) | hexvalue(ch);

        if (verbose > 3)
            printf("inlen=%d state=%s ch=0x%02x/%c %s/%02x value=0x%04x\n",
                    inlen,
                    (state == sOFFSET ? "sOFFSET" :
                     state == sBYTE1 ? "sBYTE1" :
                     state == sBYTE2 ? "sBYTE2" :
                     state == sGAP1 ? "sGAP1" :
                     state == sGAP2 ? "sGAP2" :
                     state == sEXTRA ? "sEXTRA" : "???"),
                    ch, ch, 
                    ishex(ch) ? "hex" : "-",
                    ishex(ch) ? hexvalue(ch) : 0,
                    value);

        switch (state) {
        case sOFFSET:
            if (ch == ' ' || ishex(ch))
                break;
            if (ch != ':') 
                errx(1, "expected colon, space or hex");
            if (value != inlen)
                errx(1, "offset mismatch %x != %x", value, inlen);
            state = sGAP1;
            break;
        case sGAP1:
            if (ch != ' ')
                errx(1, "expected space");
            if ((inlen % 16) == 8)
                state = sGAP2;
            else {
                state = sBYTE1;
                value = 0;
            }
            break;
        case sGAP2:
            if (ch != ' ')
                errx(1, "expected space");
            state = sBYTE1;
            break;
        case sBYTE1:
            if (ch == ' ')
                state = sEXTRA;
            else if (!ishex(ch))
                errx(1, "expected space or hex");
            else
                state = sBYTE2;
            break;
        case sBYTE2:
            if (!ishex(ch))
                errx(1, "expected 2nd digit for byte");
            if (inlen >= bufsz)
                errx(1, "input too long: %d", bufsz);
            inbuf[inlen++] = value;
            if (inlen % 16 == 0)
                state = sEXTRA;
            else
                state = sGAP1;
            break;
        case sEXTRA:
            if (ch == '\r' || ch == '\n') {
                value = 0;
                state = sOFFSET;
            }
            break;
        }
    }
    return inlen;
}

int
main(int argc, char **argv)
{
    char inbuf[65535];
    int inlen;
    int ch;
    int error = 0;
    FILE *input = stdin;
    char *input_name = "<stdin>";
    struct dns_msg *msg;
    int is_raw = 0;

    while ((ch = getopt(argc, argv, "rv")) != -1)
	switch (ch) {
	case 'v':
	    verbose++;
	    break;
	case 'r':
	    is_raw=1;
	    break;
	default:
	    error = 1;
	}

    if (optind < argc && !error) {
        input_name = argv[optind++];
        input = fopen(input_name, "rb");
        if (!input)
            err(1, "%s", input_name);
    }

    if (optind != argc)
        error = 1;

    if (error) {
	fprintf(stderr, "usage: %s [-v] [file]\n", argv[0]);
	exit(1);
    }

    if (is_raw)
        inlen = read_raw(input, inbuf, sizeof inbuf);
    else
        inlen = read_hex(input, inbuf, sizeof inbuf);

    if (ferror(input))
        err(1, "%s", input_name);

    dumphex(inbuf, inlen);

    msg = dns_msg_new();
    dns_msg_setbuf(msg, inbuf, inlen);
    dumpmsg(msg);
    dns_msg_free(msg);

    exit(0);
}
