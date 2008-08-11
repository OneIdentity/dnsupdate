
/* A file stream context, with one-character lookahead and line counting */
struct stream {
    FILE *file;
    int ch;
    const char *path;
    unsigned int lineno;
};

/* A simple string buffer that can grow */
struct buffer {
    unsigned int alloc, len;
    char *data;
};

void  buffer_append(struct buffer *buffer, int ch);
void  buffer_init(struct buffer *buffer);
void  buffer_fini(struct buffer *buffer);
char *buffer_string(struct buffer *buffer);
void  buffer_rtrim(struct buffer *buffer, const char *cset);
int   stream_init_path(struct stream *s, const char *path);
int   stream_init(struct stream *s, const char *path, FILE *file);
void  stream_fini(struct stream *s);
void  stream_error(struct stream *s, const char *msg);
int   stream_getch(struct stream *s);
int   stream_nextch(const struct stream *s);
int   stream_ok(const struct stream *s);
void  stream_until(struct stream *s, const char *cs, struct buffer *b);
void  stream_while(struct stream *s, const char *cs, struct buffer *b);
