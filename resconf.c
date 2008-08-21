
/*
 * Records resolver configuration, as read from /etc/resolv.conf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "resconf.h"
#include "stream.h"
#include "list.h"

extern int verbose;

/* Private storage for resolver configuration strings */
static struct {
    char *nameserver, *domain, *search;
} resconf;

static void load_resolv_file(const char *path);
static char **to_field(const char *name);


/* Reads lines from resolv.conf and calls resconf_set() to set options */
void
resconf_init()
{
    char *localdomain;
    const char *resconf_path;

    resconf_path = getenv("DNS_RESOLV_CONF");
    if (resconf_path && *resconf_path)
	fprintf(stderr, "using DNS_RESOLV_CONF %s\n", resconf_path);
    else
	resconf_path = "/etc/resolv.conf";
    load_resolv_file(resconf_path);

    /* The environment variable LOCALDOMAIN overrides search */
    localdomain = getenv("LOCALDOMAIN");
    if (localdomain && *localdomain) {
	if (verbose)
	    fprintf(stderr, "using LOCALDOMAIN %s\n", localdomain);
	resconf_set("search", localdomain);
    }
}

static void
load_resolv_file(const char *path)
{
    struct stream stream;
    struct buffer option;
    struct buffer arg;
    int oldlen;
    char **field, *fieldch;

#define WHITESPACE  " \t"
#define ENDOFLINE   "\n"
#define IDENTIFIER  "a-zA-Z_0-9."

    if (!stream_init_path(&stream, path))
	return;
    buffer_init(&option);
    buffer_init(&arg);
    for (;;) {
	stream_while(&stream, ENDOFLINE, NULL);	    /* skip line end(s) */
	stream_while(&stream, WHITESPACE, NULL);    /* skip leading whitesp */
	if (!stream_ok(&stream))
	    break;
	option.len = 0;
	stream_while(&stream, IDENTIFIER, &option);  /* read word */
	if (!option.len) {
	    /* Ignore bad identifiers */
	    stream_until(&stream, ENDOFLINE, NULL); /* ignore rest of line */
	    continue;
	}
	buffer_append(&option, '\0');
	arg.len = 0;
	/* Copy old field value into arg first */
	field = to_field(option.data);
	if (field && *field) 
	    for (fieldch = *field; *fieldch; fieldch++)
		buffer_append(&arg, *fieldch);
	for (;;) {
	    stream_while(&stream, WHITESPACE, NULL);    /* skip whitesp */
	    if (arg.len)
		buffer_append(&arg, ' ');
	    oldlen = arg.len;
	    stream_until(&stream, WHITESPACE ENDOFLINE, &arg);
	    if (oldlen == arg.len) {			/* no more words */
		arg.len--;				/* kill last space */
		break;
	    }
	}
	stream_until(&stream, ENDOFLINE, NULL);
	buffer_append(&arg, '\0');
	resconf_set(option.data, arg.data);
    }
    buffer_fini(&arg);
    buffer_fini(&option);
    stream_fini(&stream);
}

/* Returns an internal pointer to the correct resconf field */
static char **
to_field(const char *name)
{
    if (strcmp(name, "nameserver") == 0)
	return &resconf.nameserver;
    else if (strcmp(name, "domain") == 0)
	return &resconf.domain;
    else if (strcmp(name, "search") == 0)
	return &resconf.search;
    else
	return NULL;
}

/* Returns an array of strings for the given option, or NULL if the
 * option is unknown. */
char **
resconf_get(const char *option)
{
    char **ptr;

    if (!(ptr = to_field(option)))
	return NULL;
    return list_from_string(*ptr ? *ptr : "");
}

/* Free list returned by resconf_get.  */
void
resconf_free(char **argv)
{
    list_free(argv);
}

/* Sets a resolver option. Unknown options are ignored. */
void
resconf_set(const char *option, const char *arg)
{
    char **ptr;

    if (!*arg)				    /* Ignore when argument missing */
	return;
    if (!(ptr = to_field(option)))
	return;				    /* Ignore unknown option names */
    if (*ptr)
	free(*ptr);			    /* Free old option */
    *ptr = arg ? strdup(arg) : NULL;

    /*
     * 'search' and 'domain' are mutually exclusive.
     * Setting one destroys the other
     */
    if (arg && ptr == &resconf.domain && resconf.search) {
	free(resconf.search);
	resconf.search = NULL;
    }
    if (arg && ptr == &resconf.search && resconf.domain) {
	free(resconf.domain);
	resconf.domain = NULL;
    }

    if (verbose > 2)
	fprintf(stderr, "resconf_set: set %s = %s\n", option, 
		*ptr ? *ptr : "(null)");
}
