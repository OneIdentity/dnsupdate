/* (c) 2006, Quest Software, Inc. All rights reserved. */
/* David Leonard, 2006 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdio.h>
#endif

/*
 * Simple getopt implementation, for platforms without it.
 */

char *optarg;
int optind = 1, opterr = 1, optopt;
int optidx = 0;

int
getopt(int argc, char * const argv[], const char *optstring)
{
    const char *p;
    char ch;

    if (argv[optind] == NULL || *argv[optind] != '-' || !argv[optind][1])
	return -1;

    ch = argv[optind][optidx + 1];

    if (ch == '-' && optidx == 0 && !argv[optind][2]) {
        optind++;
        optidx = 0;
        return -1;
    }

    p = optstring;
    if (*p == ':')
	p++;
    while (*p) {
	if (*p == ch) 
	    break;
	p++;
	if (*p == ':')
	    p++;
    }

    if (!*p) {
	optopt = ch;
	if (*optstring != ':')
	    fprintf(stderr, "unknown option -%c\n", ch);
	if (argv[optind][optidx + 2] == '\0') {
	    optind++;
	    optidx = 0;
	} else 
	    optidx++;
	return '?';
    }

    if (p[1] == ':') {
	if (argv[optind][optidx + 2]) 
	    optarg = argv[optind] + optidx + 2;
	else {
	    optarg = argv[++optind];
	    if (!optarg) {
		if (*optstring != ':')
		    fprintf(stderr, "missing argument to -%c\n", *p);
		optopt = *p;
		return ':';
	    }
	}
	optind++;
	optidx = 0;
    } else if (argv[optind][optidx + 2] == '\0') {
	optind++;
	optidx = 0;
    } else 
	optidx++;
    return *p;
}

#if TEST
int
main(int argc, char **argv)
{
    int ch;

    while ((ch = getopt(argc, argv, "ab:c:")) != -1)
	switch (ch) {
	    case 'a': printf("got -a\n"); break;
	    case 'b': printf("got -b optarg=%s\n", optarg); break;
	    case 'c': printf("got -c optarg=%s\n", optarg); 
		      printf("       2nd arg: %s\n", argv[optind++]);
		      break;
	    default: printf("error '%c' optopt=%c\n", ch, optopt);
	}
    while (optind < argc)
	printf("extra arg: %s\n", argv[optind++]);
    exit(0);
}
#endif
