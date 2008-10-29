/* (c) 2008 Quest Software, Inc. All rights reserved. */

#include </usr/include/err.h>
#include <alloca.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include "watch.h"

/*
 * Watch keys changing in a SC Dynamic store and call callbacks
 * when they change.
 */

static CFMutableDictionaryRef watch_dict;
static SCDynamicStoreRef watch_store;

static void watch_dict_changed(void);
static void notify_watched_key_changed(const void *value, void *context);

/*
 * Initialises the watch list
 */
void
watch_init(SCDynamicStoreRef store)
{
	watch_store = store;
	watch_dict = CFDictionaryCreateMutable(NULL, 0, 
		&kCFTypeDictionaryKeyCallBacks, NULL);
	if (!watch_dict)
	    errx(1, "CFDictionaryCreateMutable");
}

/*
 * Add a key to watch in configd, and a callback to call when we
 * get a notification of change.
 */
void
watch_add_key(CFStringRef key, void (*callback)(void))
{
	CFDictionarySetValue(watch_dict, key, callback);
	watch_dict_changed();
}

/*
 * Remove a key added through watch_add_key()
 */
void
watch_remove_key(CFStringRef key)
{
	CFDictionaryRemoveValue(watch_dict, key);
	watch_dict_changed();
}

/*
 * Updates the Dynamic Store notification with the new list of keys to
 * watch. 
 */
static void
watch_dict_changed()
{
	const void **keys;
	int nkeys;
	CFArrayRef array;

	nkeys = CFDictionaryGetCount(watch_dict);
	keys = (const void **)alloca(nkeys * sizeof (const void *));
	CFDictionaryGetKeysAndValues(watch_dict, keys, NULL);

	array = CFArrayCreate(NULL, keys, nkeys, &kCFTypeArrayCallBacks);
	if (!array)
	    errx(1, "CFArrayCreate");
	if (!SCDynamicStoreSetNotificationKeys(watch_store, array, NULL))
	    errx(1, "SCDynamicStoreSetNotificationKeys: %s", 
		    SCErrorString(SCError()));
	CFRelease(array);
}

/*
 * Called when a collection of watched keys change in the dynamic store.
 * This function is given as an argument to SCDynamicStoreCreate().
 */
void
watch_store_callback(SCDynamicStoreRef store, CFArrayRef changedKeys, 
	void *info)
{
	CFArrayApplyFunction(changedKeys, 
		CFRangeMake(0, CFArrayGetCount(changedKeys)),
		notify_watched_key_changed, NULL);
}

/*
 * Called when a single key changes in the dynamic store.
 * Dispatches to the right notification.
 */
static void
notify_watched_key_changed(const void *value, void *context)
{
	void (*callback)(void);

	assert(value != NULL);
	callback = CFDictionaryGetValue(watch_dict, value);
	if (callback)
	    (*callback)();
}
