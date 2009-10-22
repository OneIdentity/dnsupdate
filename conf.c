/* (c) 2008, Quest Software, Inc. All rights reserved. */

/*
 * Simple key-value configuration file interface
 */

#include "common.h"
#include "conf.h"
#include "err.h"
#include "stream.h"

extern int verbose;

/* A configuration entry */
struct config {
    char *key, *value;
    struct config *next;
};

/* Prototypes */
static const struct config *config_get(const char *key);
static void config_load_stream(struct stream *stream);

/* A stack of configuration entries. New config entries are pushed onto the
 * top of the stack. Searches are performed top-down into the stack. */
static struct config *Config;

/*------------------------------------------------------------
 * Public functions
 */

/* Adds a key/value settings into the global configuration */
void
config_add(char *key, char *value)
{
    struct config *config;

    if (!(config = (struct config *)malloc(sizeof *config))) {
	fprintf(stderr, "config_add: out of memory\n");
	exit(1);
    }
    config->key = key;
    config->value = value;
    config->next = Config;
    Config = config;
    if (verbose > 2)
	fprintf(stderr, "config_add: %s = %s\n", key, value);
}

/* Adds settings from a configuration file into the global configuration. */
void
config_load(const char *path)
{
    struct stream stream;
   
    if (verbose > 2)
	fprintf(stderr, "config_load %s\n", path);
    if (!stream_init_path(&stream, path)) {
	if (verbose)
	    warn("%s", path);
	return;
    }
    config_load_stream(&stream);
    stream_fini(&stream);
}

/* Returns a configuration value as an integer.
 * Returns def_value if no prior configuration is found.
 * The strings 'yes', 'true', and 'on' are converted to 1.
 * Numbers beginning with 0x are converted using base 16. 
 * Numbers beginning with 0 are converted using base 8.
 * Non-numeric digits are otherwise ignored.
 * A value with no digits is returned as zero. */
long 
config_get_int(const char *key, long def_value)
{
    const struct config *config;
   
    if (!(config = config_get(key)))
	return def_value;
    if (strcmp(config->value, "yes") == 0 ||
	strcmp(config->value, "true") == 0 ||
	strcmp(config->value, "on") == 0)
	    return 1;
    return strtol(config->value, NULL, 0);
}

/* Returns a configuration value as a nul-terminated C string. 
 * Returns def_value if the configuration is not found.
 * Caller must NOT free or alter the returned string. */
const char *
config_get_string(const char *key, const char *def_value)
{
    const struct config *config;
   
    if (!(config = config_get(key)))
	return def_value;
    return config->value;
}

/* Returns nonzero if a configuration setting is set explicitly,
 * or zero if it is not set.
 */
int
config_is_set(const char *key)
{
    if (config_get(key))
	return 1;
    return 0;
}

/*------------------------------------------------------------
 * Private config functions
 */

/* Returns a configuration entry for the given key, or NULL if not found */
static const struct config *
config_get(const char *key)
{
    struct config *config;

    for (config = Config; config; config = config->next)
	if (strcmp(key, config->key) == 0)
	    return config;
    return NULL;
}

/* Loads configuration statements from the stream into the global Config */
static void
config_load_stream(struct stream *stream)
{
    char *key, *value;
    struct buffer buffer;

    buffer_init(&buffer);

#define WHITESPACE  " \t"
#define ENDOFLINE   "\n\r"

    for (;;) {
	/* Ignore to the end of the previous line */
	stream_while(stream, ENDOFLINE, NULL);	    /* skip line end(s) */
	stream_while(stream, WHITESPACE, NULL);	    /* skip lead whitespace */
	if (!stream_ok(stream))			    /* check for end of file */
	    break;
	if (stream_nextch(stream) == '#') {	    /* comments start with # */
	    stream_until(stream, ENDOFLINE, NULL);  /* skip to end of line */
	    continue;
	}
	buffer.len = 0;
	stream_until(stream, "#=" WHITESPACE, &buffer);	/* read key word */
	if (!buffer.len) {
	    stream_error(stream, "missing key");
	    stream_until(stream, ENDOFLINE, NULL);  /* skip to end of line */
	    continue;
	}
	stream_while(stream, WHITESPACE, NULL);     /* skip whitespace */
	if (stream_nextch(stream) != '=') {	    /* expect '=' */
	    stream_error(stream, "expected '='");
	    stream_until(stream, ENDOFLINE, NULL);  /* skip to end of line */
	    continue;
	}
	stream_getch(stream);			    /* skip '=' */
	key = buffer_string(&buffer);		    /* also clears buffer */
	stream_while(stream, WHITESPACE, NULL);	    /* skip whitespace */
	stream_until(stream, "#" ENDOFLINE, &buffer); /* read value */
	buffer_rtrim(&buffer, WHITESPACE);	    /* remove trailing space */
	value = buffer_string(&buffer);		    /* extract value */
	config_add(key, value);
    }
    buffer_fini(&buffer);
}
