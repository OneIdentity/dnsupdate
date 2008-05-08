/* (c) 2008 Quest Software, Inc. All rights reserved. */

#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "watch.h"

/*
 * ipwatchd is a Mac OS X daemon that watches for IP address changes and
 * then executes a given command.
 * 
 * It is a replacement for the 'kicker' daemon which was removed in 
 * Mac OS 10.5 (Leopard).
 * 
 * This daemon watches the following dynamic store string
 *   State:/Network/Global/IPv4[PrimaryService]
 * to determine what the current "primary" interface (eg "0", meaning en0)
 * From this it watches the primary service's IP address(es) at
 *   State:/Network/Service/$PrimaryService/IPv4[Addresses] 
 * And uses the first IP address as the primary address of the host.
 *
 * Changes in the primary address of the host cause an external program
 * to be run.
 */

#define ksState_Network_Global_IPv4 "State:/Network/Global/IPv4"
#define ksState_Network_Service	    "State:/Network/Service"
#define ksIPv4			    "IPv4"

static Boolean strings_equal(CFTypeRef s1, CFTypeRef s2);
static void notify_global_ipv4_change(void);
static void set_primary_service(CFStringRef newPrimaryService);
static void notify_primary_service_change(void);
static void notify_primary_ipv4_change(void);
static void set_primary_address(CFStringRef newPrimaryAddress);
static void notify_primary_address_change(void);

static int debug = 0;
static SCDynamicStoreRef DynamicStore;
static CFStringRef GlobalIPv4Key = NULL;  /* "State:/Network/Global/IPv4" */
static CFStringRef PrimaryService = NULL;   /* eg "0" */
static CFStringRef PrimaryIPv4Key = NULL; /* "State:/Network/Service/${PrimaryService}/IPv4" */
static CFStringRef PrimaryAddress = NULL;   /* eg "1.2.3.4" */


int
main(int argc, char * const argv[])
{
	int error = 0;
	int ch;
	extern int optind;

	while ((ch = getopt(argc, argv, "d")) != -1)
		switch (ch) {
		case 'd':
		    debug = 1;
		    break;
		case '?':
		    error = 1;
		    break;
		}
	if (optind < argc)
		error = 1;
	if (error) {
		fprintf(stderr, "usage: %s [-d]\n", argv[0]);
		exit(1);
	}

	GlobalIPv4Key = CFSTR(ksState_Network_Global_IPv4);

	/* Open SC's dynamic store, which is updated by configd */
	DynamicStore = SCDynamicStoreCreate(NULL, CFSTR("ipwatchd"),
		    watch_store_callback, NULL);
	if (!DynamicStore)
		errx(1, "SCDynamicStoreCreate: %s", SCErrorString(SCError()));


	/* Subscribe to changes in State:/Network/Global/IPv4 
	 * which indicates a change in primary interface */
	watch_init(DynamicStore);
	watch_add_key(GlobalIPv4Key, notify_global_ipv4_change);

	/* Connect the dynamic store notifications into the current run loop */
	CFRunLoopAddSource(CFRunLoopGetCurrent(),
	    SCDynamicStoreCreateRunLoopSource(NULL, DynamicStore, 0),
	    kCFRunLoopCommonModes);

	/* Trigger a change notification now */
	notify_global_ipv4_change();

	/* Wait for events */
	CFRunLoopRun();
	exit(0);
}

/* Returns true if two string pointers are either both NULL, or the same text.
 */
static Boolean
strings_equal(CFTypeRef s1, CFTypeRef s2)
{
    if (!s1 && !s2)
	return TRUE;
    if (!s1 || !s2)
	return FALSE;
    return CFEqual(s1, s2);
}

/*
 * Called when State:/Network/Global/IPv4 properties may have changed.
 * Checks to see if the Primary Service has changed
 */
static void
notify_global_ipv4_change()
{
	CFPropertyListRef GlobalIPv4Prop;
	CFTypeRef newPrimaryService = NULL;

	/*  get State:/Network/Global/IPv4[PrimaryService] */
	GlobalIPv4Prop = SCDynamicStoreCopyValue(DynamicStore, GlobalIPv4Key);
	if (!GlobalIPv4Prop)
	    warnx("SCDynamicStoreCopyValue: %s", SCErrorString(SCError()));
	else
	    newPrimaryService = CFDictionaryGetValue(GlobalIPv4Prop, 
		    CFSTR("PrimaryService"));

	set_primary_service(newPrimaryService);
}

/* Set PrimaryService to a new string */
static void
set_primary_service(CFStringRef newPrimaryService)
{
	/* Ignore if the primary service doesn't change */
	if (strings_equal(PrimaryService, newPrimaryService))
	    return;

	if (PrimaryService)
	    CFRelease(PrimaryService);
	PrimaryService = newPrimaryService;
	if (PrimaryService)
	    CFRetain(PrimaryService);
	notify_primary_service_change();
}

/*
 * Called when PrimaryService changes.
 * Updates subscriptions and then checks for a new address.
 */
static void
notify_primary_service_change()
{
	CFTypeRef elements[3];
	CFArrayRef array;

	if (PrimaryIPv4Key) {
	    watch_remove_key(PrimaryIPv4Key);
	    CFRelease(PrimaryIPv4Key);
	    PrimaryIPv4Key = NULL;
	}

	if (!PrimaryService) {
	    /* We lost the primary service, so we lose the address */
	    set_primary_address(NULL);
	    return;
	}

	/* Construct "State:/Network/Service/${PrimaryService}/IPv4" */
	elements[0] = CFSTR(ksState_Network_Service);
	elements[1] = PrimaryService;
	elements[2] = CFSTR(ksIPv4);
	array = CFArrayCreate(NULL, elements, 3, &kCFTypeArrayCallBacks);
	if (!array)
	    errx(1, "CFArrayCreate");
	PrimaryIPv4Key = CFStringCreateByCombiningStrings(NULL, array, 
		CFSTR("/"));
	if (!PrimaryIPv4Key)
	    errx(1, "CFStringCreateByCombiningStrings");
	CFRelease(array);

	/* Start watching the new Primary service's IPv4 state key */
	watch_add_key(PrimaryIPv4Key, notify_primary_ipv4_change);
	/* Trigger an immediate change notification to get its value */
	notify_primary_ipv4_change();
}

/*
 * Called when we think the State:/Network/Service/${PrimaryService}/IPv4
 * property has changed.
 */
static void
notify_primary_ipv4_change()
{
	CFPropertyListRef prop;
	CFArrayRef addresses;
	CFTypeRef newPrimaryAddress = NULL;

	assert(PrimaryIPv4Key != NULL);

	/*  get State:/Network/Service/${primaryService}/IPv4[Addresses] */
	prop = SCDynamicStoreCopyValue(DynamicStore, PrimaryIPv4Key);
	if (!prop)
	    warnx("SCDynamicStoreCopyValue: %s", SCErrorString(SCError()));
	else {
	    addresses = CFDictionaryGetValue(prop, CFSTR("Addresses"));
	    if (addresses && CFArrayGetCount(addresses) > 0)
		newPrimaryAddress = CFArrayGetValueAtIndex(addresses, 0);
	}

	set_primary_address(newPrimaryAddress);
	CFRelease(prop);
}

/*
 * Sets PrimaryAddress to the given value
 */
static void
set_primary_address(CFStringRef newPrimaryAddress)
{
	/* Ignore if the address doesn't change */
	if (strings_equal(PrimaryAddress, newPrimaryAddress))
	    return;

	if (PrimaryAddress)
	    CFRelease(PrimaryAddress);
	PrimaryAddress = newPrimaryAddress;
	if (PrimaryAddress)
	    CFRetain(PrimaryAddress);
	notify_primary_address_change();
}

/*
 * Called when PrimaryAddress changes its value.
 */
static void
notify_primary_address_change()
{
	/* XXX TBD */
	fprintf(stderr, "Primary address is now: ");
	CFShow(PrimaryAddress); /* XXX may be NULL meaning no address */
}

