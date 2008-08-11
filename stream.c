/* (c) 2008, Quest Software, Inc. All rights reserved. */

/*
 * Simple single-lookahead, buffered file reader which is really
 * a primitive lexical analyser.
 */

#include <stdio.h>
#include <stdlib.h>

#include "stream.h"

/* Prototypes */
static int  in_set(int ch, const char *char_set);

/*------------------------------------------------------------
 * Buffer functions
 */

/* Appends a single char to the buffer. NULL buffers are silently ignored. */
void
buffer_append(struct buffer *buffer, int ch)
{
    if (!buffer)
	return;

    if (buffer->len >= buffer->alloc) {
	char *newdata;
	unsigned int newalloc;
	if (buffer->alloc) {
	    newalloc = buffer->alloc * 2;
	    newdata = realloc(buffer->data, newalloc);
	} else {
	    newalloc = 64;
	    newdata = malloc(newalloc);
	}
	if (!newalloc) {
	    fprintf(stderr, "buffer_append: out of memory for %u\n", newalloc);
	    exit(1);
	}
	buffer->alloc = newalloc;
	buffer->data = newdata;
    }
    buffer->data[buffer->len++] = ch;
}

/* Initializes a buffer to empty */
void
buffer_init(struct buffer *buffer)
{
    buffer->alloc = 0;
    buffer->len = 0;
    buffer->data = NULL;
}

/* Releases storage from the buffer */
void
buffer_fini(struct buffer *buffer)
{
    if (buffer->alloc)
	free(buffer->data);
    buffer_init(buffer);
}

/* Converts the buffer to a nul-terminated string and then resets the buffer.
 * Caller must free resulting (non-NULL) string. */
char *
buffer_string(struct buffer *buffer)
{
    char *s;

    buffer_append(buffer, '\0');
    s = buffer->data;	    /* Take ownership of buffer->data */
    buffer_init(buffer);    /* Reset the buffer which zeros buffer->data */
    return s;
}

/* Removes characters from the end of the buffer that are in the char set */
void
buffer_rtrim(struct buffer *buffer, const char *cset)
{
	while (buffer->len && in_set(buffer->data[buffer->len - 1], cset))
	    buffer->len--;
}

/*------------------------------------------------------------
 * Stream functions
 */

/* Initialises a stream context using the file described by |path|.
 * Returns true on success. */
int
stream_init_path(struct stream *s, const char *path)
{
    FILE *file;

    if (!(file = fopen(path, "r")))
	return 0;
    return stream_init(s, path, file);
}

/* Initialises the stream using the pre-opened FILE handle.
 * The name of the file should be provided in |path| for error messages.
 * Returns true on success. */
int
stream_init(struct stream *s, const char *path, FILE *file)
{
    s->file = file;
    s->ch = fgetc(s->file);
    s->lineno = 1;
    s->path = path;
    return 1;
}

/* Finalizes a stream, closing its FILE handle and marking it at EOF. */
void
stream_fini(struct stream *s)
{
    s->ch = EOF;
    if (s->file) {
	fclose(s->file);
	s->file = NULL;
    }
}

/* Prints an error message prefixed by the stream position.
 * For example, "<path>:<lineno>: <message>\n" */
void
stream_error(struct stream *s, const char *msg)
{
    fprintf(stderr, "%s:%d: %s\n", s->path ? s->path : "?", s->lineno, msg);
}

/* Reads the stream and returns the next character. */
int
stream_getch(struct stream *s)
{
    int ch = s->ch;

    if (ch != EOF)
	s->ch = fgetc(s->file);
    if (ch == '\n')
	s->lineno++;
    return ch;
}

/* Returns the next character that stream_getch() would return without
 * modifying the stream. */
int
stream_nextch(const struct stream *s)
{
    return s->ch;
}

/* Return true if a call to stream_nextch() wouldn't return EOF */
int
stream_ok(const struct stream *s)
{
    return s->ch != EOF;
}

/* Returns true if ch is in the char_set.
 * The charset is a list of characters terminated by nul.
 * A character followed by a hyphen indicates a range. 
 * If hyphen is supposed to be in the set, then it should be the first char.
 */
static int
in_set(int ch, const char *char_set)
{
    const char *cs;
    char lo;

    for (cs = char_set; *cs; cs++) {
	if (*cs == ch)
	    return 1;
	if (cs[1] == '-') {
	    lo = *cs;
	    cs += 2;
	    if (lo <= ch && ch <= *cs)
		return 1;
	}
    }
    return 0;
}

/* Reads characters from stream up to but not including a character from
 * the char_set. */
void
stream_until(struct stream *s, const char *char_set, struct buffer *buf)
{
	while (stream_ok(s)) {
	    if (in_set(stream_nextch(s), char_set))
		break;
	    buffer_append(buf, stream_getch(s));
	}
}

/* Reads from the stream whileever characters found in char_set would be
 * read. */
void
stream_while(struct stream *s, const char *char_set, struct buffer *buf)
{
	while (stream_ok(s)) {
	    if (!in_set(stream_nextch(s), char_set))
		break;
	    buffer_append(buf, stream_getch(s));
	}
}
