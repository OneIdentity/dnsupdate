void watch_init(SCDynamicStoreRef store);
void watch_add_key(CFStringRef key, void (*callback)(void));
void watch_remove_key(CFStringRef key);
void watch_store_callback(SCDynamicStoreRef, CFArrayRef, void *);
