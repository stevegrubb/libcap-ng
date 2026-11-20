/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* process_caps_test.c -- capability snapshot read error tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"
#include "../cap-ng.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#if defined(PR_CAPBSET_DROP) && defined(PR_CAP_AMBIENT)

static int bounds_error;
static int ambient_error;
static unsigned int bounds_calls;
static unsigned int ambient_calls;
static unsigned int capget_calls;

static void check(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(EXIT_FAILURE);
	}
}

int capget(cap_user_header_t header, const cap_user_data_t data)
{
	struct __user_cap_data_struct caps[2] = { { 0 }, { 0 } };

	header->version = _LINUX_CAPABILITY_VERSION_3;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	capget_calls++;
	caps[0].effective = 1U << CAP_CHOWN;
	caps[0].permitted = 1U << CAP_CHOWN;
	memcpy(data, caps, sizeof(caps));
	return 0;
}

FILE *fopen(const char *path, const char *mode)
{
	(void)path;
	(void)mode;
	/* Force prctl fallback so host procfs cannot hide an injected error. */
	errno = ENOENT;
	return NULL;
}

int prctl(int option, ...)
{
	va_list args;
	unsigned int capability;
	int error;

	va_start(args, option);
	if (option == PR_CAPBSET_READ) {
		capability = va_arg(args, unsigned int);
		error = bounds_error;
		bounds_calls++;
	} else if (option == PR_CAP_AMBIENT) {
		check(va_arg(args, int) == PR_CAP_AMBIENT_IS_SET,
		      "Unexpected ambient operation");
		capability = va_arg(args, unsigned int);
		error = ambient_error;
		ambient_calls++;
	} else {
		va_end(args);
		errno = EINVAL;
		return -1;
	}
	va_end(args);
	if (error) {
		errno = error;
		return -1;
	}
	/* Match the library's two-word storage during capability discovery. */
	if (capability >= 64) {
		errno = EINVAL;
		return -1;
	}
	return capability == CAP_CHOWN;
}

static void test_read(int bounds_errno, int ambient_errno, int expected_errno)
{
	void *saved = capng_save_state();
	int rc, read_errno;

	check(saved != NULL, "Failed to save the initialized capability state");
	bounds_error = bounds_errno;
	ambient_error = ambient_errno;
	bounds_calls = ambient_calls = capget_calls = 0;
	errno = 0;
	rc = capng_get_caps_process();
	read_errno = errno;
	if (expected_errno) {
		check(rc == -1, "Capability read returned success after failure");
		check(read_errno == expected_errno,
		      "Capability read lost the first failure's errno");
		check(capng_have_capabilities(CAPNG_SELECT_ALL) == CAPNG_FAIL,
		      "Failed capability snapshot was accepted");
	} else {
		check(rc == 0, "Successful capability read returned failure");
		check(capng_have_capability(CAPNG_EFFECTIVE, CAP_CHOWN) &&
		      capng_have_capability(CAPNG_BOUNDING_SET, CAP_CHOWN) &&
		      capng_have_capability(CAPNG_AMBIENT, CAP_CHOWN),
		      "Successful read lost capability set contents");
	}
	check(capget_calls == 1, "Expected one process capability read");
	check(bounds_calls > 0, "Bounding queries were not exercised");
	if (!bounds_errno)
		check(ambient_calls > 0, "Ambient queries were not exercised");
	/* Each case starts with a usable state, including after CAPNG_ERROR. */
	capng_restore_state(&saved);
}

int main(void)
{
	/* Complete feature detection while every mocked query can succeed. */
	capng_clear(CAPNG_SELECT_ALL);
	test_read(0, 0, 0);
	test_read(EPERM, 0, EPERM);
	test_read(0, EACCES, EACCES);
	test_read(EPERM, EACCES, EPERM);
	puts("Process capability read error tests passed");
	return EXIT_SUCCESS;
}
#else
int main(void)
{
	return 77;
}
#endif
