void config_add(char *key, char *value);
void config_load(const char *path);
long config_get_int(const char *key, long def_value);
const char *config_get_string(const char *key, const char *def_value);
