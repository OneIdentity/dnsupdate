void   resconf_init(void);
char **resconf_get(const char *option);
void   resconf_free(char **list);
void   resconf_set(const char *option, const char *arg);
