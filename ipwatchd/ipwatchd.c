/* (c) 2008 Quest Software, Inc. All rights reserved. */

#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <launch.h>
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

static void checkin(void);
static Boolean strings_equal(CFTypeRef s1, CFTypeRef s2);
static void notify_global_ipv4_change(void);
static void set_primary_service(CFStringRef newPrimaryService);
static Boolean substitute_pattern(const char *pattern, 
	const char *substitution, char *buf, int bufsz);
static void notify_primary_service_change(void);
static void notify_primary_ipv4_change(void);
static void set_primary_address(CFStringRef newPrimaryAddress);
static void notify_primary_address_change(void);
static void run_change_program(CFRunLoopTimerRef timer, void *info);

/* Configuration */
static const char *GlobalIPv4Key;
static const char *PrimaryIPv4KeyPattern;
static const char *ChangeProgram;
static double      ChangeDelay = -1;			  /* seconds */
static int         debug;

static SCDynamicStoreRef DynamicStore;
static CFRunLoopTimerRef ChangeTimer;

/* Cached strings from configuration */
static CFStringRef PrimaryService = NULL; /* "0" */
static CFStringRef PrimaryIPv4Key = NULL; /* "State:/Network/Service/0/IPv4" */
static CFStringRef PrimaryAddress = NULL; /* "1.2.3.4" */


int
main(int argc, char * const argv[])
{
	int error = 0;
	int ch;
	extern int optind;
	CFStringRef key;

	while ((ch = getopt(argc, argv, "d")) != -1)
		switch (ch) {
		case 'd':
		    debug = TRUE;
		    break;
		case '?':
		    error = 1;
		    break;
		}
	if (optind < argc)
		ChangeProgram = argv[optind++];

	if (optind < argc)
		error = 1;
	if (error) {
		fprintf(stderr, "usage: %s [-d] [ChangeProgram]\n", argv[0]);
		exit(1);
	}

	checkin();

	/* Set defaults */
	if (!GlobalIPv4Key)
		GlobalIPv4Key = "State:/Network/Global/IPv4";
	if (!PrimaryIPv4KeyPattern)
		PrimaryIPv4KeyPattern = "State:/Network/Service/%/IPv4";
	if (ChangeDelay < 0)
		ChangeDelay = 30;

	/* Display the configuration results */
	if (debug) {
		fprintf(stderr, "ChangeProgram: %s\n",
		    ChangeProgram ? ChangeProgram : "(null)");
		fprintf(stderr, "GlobalIPv4Key: %s\n", GlobalIPv4Key);
		fprintf(stderr, "PrimaryIPv4KeyPattern: %s\n", 
		    PrimaryIPv4KeyPattern);
		fprintf(stderr, "ChangeDelay: %f\n", ChangeDelay);
	}

	/* Open SC's dynamic store, which is updated by configd */
	DynamicStore = SCDynamicStoreCreate(NULL, 
	    CFSTR("com.quest.rc.ipwatchd"), watch_store_callback, NULL);
	if (!DynamicStore)
		errx(1, "SCDynamicStoreCreate: %s", SCErrorString(SCError()));

	/* Subscribe to changes in State:/Network/Global/IPv4 
	 * which indicates a change in primary interface */
	watch_init(DynamicStore);

	key = CFStringCreateWithCString(NULL, GlobalIPv4Key, 
	    kCFStringEncodingMacRoman);
	if (!key)
		errx(1, "CFStringCreateWithCString");
	watch_add_key(key, notify_global_ipv4_change);
	CFRelease(key);

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

/* Check-in with launchd and receive parameters */
static void
checkin()
{
	launch_data_t checkin, response, param;

	/* Check-in with launchd */

	if (!(checkin = launch_data_new_string(LAUNCH_KEY_CHECKIN))) {
		warnx("launch_data_new_string");
		return;
	}

	if (!(response = launch_msg(checkin))) {
		warnx("launch_msg");
		return;
	}
	if (launch_data_get_type(response) == LAUNCH_DATA_ERRNO) {
		warnx("launch check-in failed: %s",
			strerror(launch_data_get_errno(response)));
		return;
	}
	if (launch_data_get_type(response) != LAUNCH_DATA_DICTIONARY) {
		warnx("launch check-in failed: bad response");
		return;
	}

	/* Extract the configuration parameters */

	param = launch_data_dict_lookup(response, "Debug");
	if (param && !debug)
		debug = launch_data_get_bool(param);

	param = launch_data_dict_lookup(response, "ChangeProgram");
	if (param && !ChangeProgram)
		ChangeProgram = launch_data_get_string(param);

	param = launch_data_dict_lookup(response, "GlobalIPv4Key");
	if (param && !GlobalIPv4Key)
		GlobalIPv4Key = launch_data_get_string(param);

	param = launch_data_dict_lookup(response, "PrimaryIPv4KeyPattern");
	if (param && !PrimaryIPv4KeyPattern)
		PrimaryIPv4KeyPattern = launch_data_get_string(param);

	param = launch_data_dict_lookup(response, "ChangeDelay");
	if (param && ChangeDelay < 0)
		ChangeDelay = launch_data_get_real(param);
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
	CFStringRef key;

	if (debug)
		fprintf(stderr, "notify_global_ipv4_change\n");

	key = CFStringCreateWithCString(NULL, GlobalIPv4Key, 
	    kCFStringEncodingMacRoman);
	if (!key)
		errx(1, "CFStringCreateWithCString");

	/*  get State:/Network/Global/IPv4[PrimaryService] */
	GlobalIPv4Prop = SCDynamicStoreCopyValue(DynamicStore, key);
	if (GlobalIPv4Prop)
		newPrimaryService = CFDictionaryGetValue(GlobalIPv4Prop, 
		    CFSTR("PrimaryService"));

	set_primary_service(newPrimaryService);

	CFRelease(key);
}

/* Set PrimaryService to a new string */
static void
set_primary_service(CFStringRef newPrimaryService)
{
	if (debug) {
		fprintf(stderr, "PrimaryService ");
		if (PrimaryService)
		    CFShow(PrimaryService); 
		else
		    fprintf(stderr, "(null)\n");
	}

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
	char service[2048];
	char key[2048];

	if (debug)
		fprintf(stderr, "notify_primary_service_change\n");

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

	/* Convert PrimaryService to a C string */
	if (!CFStringGetCString(PrimaryService, service, sizeof service,
	    kCFStringEncodingMacRoman))
	{
		warnx("CFStringGetCString(PrimaryService)");
		return;
	}

	/* Substitute the pattern with the primary service, to get
	 * "State:/Network/Service/${PrimaryService}/IPv4" */
	if (!substitute_pattern(PrimaryIPv4KeyPattern, service,
	    key, sizeof key))
	{
		warnx("substitute_pattern: string too long");
		return;
	}

	/* Convert substituted key into a CF string */
	PrimaryIPv4Key = CFStringCreateWithCString(NULL, key, 
	    kCFStringEncodingMacRoman);
	if (!PrimaryIPv4Key)
		errx(1, "CFStringCreateWithCString");

	/* Start watching the new Primary service's IPv4 state key */
	watch_add_key(PrimaryIPv4Key, notify_primary_ipv4_change);

	/* Trigger an immediate change notification */
	notify_primary_ipv4_change();
}

/* Substitute the first '%' in a pattern with a string.
 * Returns a buffer containing the pattern but with the first '%' replaced
 * with the content of the substitution string.
 */
static Boolean
substitute_pattern(const char *pattern, const char *substitution, 
	char *buf, int bufsz)
{
	const char *p;
	const char *s;
	int bufpos = 0;

	for (p = pattern; *p; p++)
		if (*p == '%' && substitution) {
		    for (s = substitution; *s; s++) {
			if (bufpos >= bufsz)
			    return FALSE;
			buf[bufpos++] = *s;
		    }
		    substitution = NULL;
		} else {
		    if (bufpos >= bufsz)
			return FALSE;
		    buf[bufpos++] = *p;
		}

	if (bufpos >= bufsz)
		return FALSE;

	buf[bufpos] = 0;
	return TRUE;
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

	if (debug)
		fprintf(stderr, "notify_primary_ipv4_change\n");

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
	if (prop)
	    CFRelease(prop);
}

/*
 * Sets PrimaryAddress to the given value
 */
static void
set_primary_address(CFStringRef newPrimaryAddress)
{
	if (debug) {
		fprintf(stderr, "PrimaryAddress ");
		if (PrimaryAddress)
		    CFShow(PrimaryAddress); 
		else
		    fprintf(stderr, "(null)\n");
	}

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
 * Arranges for the change timer to start and to call run_change_program()
 * on expiration.
 */
static void
notify_primary_address_change()
{
	CFGregorianUnits delay;

	if (debug)
		fprintf(stderr, "notify_primary_address_change\n");

	/* Start a timer to fire a short period after the address
	 * change is detected.
	 */

	if (ChangeTimer) {
		CFRunLoopTimerInvalidate(ChangeTimer);
		CFRelease(ChangeTimer);
		ChangeTimer = NULL;
	}

	/*
	 * If the primary address disappeared, then 
	 * we probably don't have a link. So forget it.
	 */
	if (!PrimaryAddress)
		return;

	/* If there is no delay required, then fire immediately */
	if (ChangeDelay <= 0) {
		run_change_program(NULL, NULL);
		return;
	}

	/* Construct a timer that will run for ChangeDelay seconds */
	memset(&delay, 0, sizeof delay);
	delay.seconds = ChangeDelay;
	ChangeTimer = CFRunLoopTimerCreate(NULL, 
	    CFAbsoluteTimeAddGregorianUnits(
		CFAbsoluteTimeGetCurrent(),
		NULL, delay),
	    0, 0, 0, run_change_program, NULL);
	if (!ChangeTimer)
		warnx("CFRunLoopTimerCreate");
	else
		CFRunLoopAddTimer(CFRunLoopGetCurrent(), 
		    ChangeTimer, kCFRunLoopCommonModes);
}

/*
 * Runs the change program, passing it the current PrimaryAddress
 * as the only argument. 
 * This function is called when the change timer expires.
 */
static void
run_change_program(CFRunLoopTimerRef timer, void *info)
{
	char address[1024];

	if (debug)
		fprintf(stderr, "run_change_program\n");

	assert(PrimaryAddress != NULL);

	if (debug) {
		fprintf(stderr, "new address: ");
		CFShow(PrimaryAddress); 
	} 

	if (!CFStringGetCString(PrimaryAddress, address,
	    sizeof address, kCFStringEncodingMacRoman))
	{
		warnx("CFStringGetCString");
		return;
	}
	
	if (ChangeProgram) {
		if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
		    warn("signal SIGCHLD");
		switch (fork()) {
		case -1: 
		    warn("fork");
		    break;
		case 0:
		    execlp(ChangeProgram, ChangeProgram, address, NULL);
		    warn("execvp: %s", ChangeProgram);
		    _exit(1);
		}
	}
}
