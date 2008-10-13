
/* A list is a null terminated array of allocated strings */
char **list_from_string(const char *s);
char **list_from_single(const char *item);
void   list_free(char **list);	/* NULL list ok */
int    list_append(char ***listp, const char *item);
char **list_dup(char **list);
char **list_new(void);
int    list_length(char **list);
void   list_remove(char **list, const char *item);
int    list_is_empty_or_null(char **list);   /* NULL list ok */
