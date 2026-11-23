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
#include <unistd.h>
#ifdef HAVE_SYSCALL_H
#include <sys/syscall.h>
#include <pthread.h>
#endif

#if defined(PR_CAPBSET_DROP) && defined(PR_CAP_AMBIENT)

static const char *status_text;
static int capget_error;
static int bounds_error;
static int ambient_error;
static unsigned int bounds_calls;
static unsigned int ambient_calls;
static unsigned int capget_calls;
static pid_t capget_pid;

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
	capget_pid = header->pid;
	if (capget_error) {
		errno = capget_error;
		return -1;
	}
	caps[0].effective = 1U << CAP_CHOWN;
	caps[0].permitted = 1U << CAP_CHOWN;
	memcpy(data, caps, sizeof(caps));
	return 0;
}

FILE *fopen(const char *path, const char *mode)
{
	(void)path;
	(void)mode;
	/* Supply only the metadata selected by the test, never host procfs. */
	if (status_text)
		return fmemopen((void *)status_text, strlen(status_text), "r");
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

static void test_capget_failure(int error)
{
	void *saved;

	bounds_error = ambient_error = 0;
	capng_clear(CAPNG_SELECT_ALL);
	check(capng_get_caps_process() == 0, "Initial snapshot read failed");
	check(capng_have_capability(CAPNG_EFFECTIVE, CAP_CHOWN),
	      "Initial snapshot lacks the test capability");
	saved = capng_save_state();
	check(saved != NULL, "Failed to save the initial snapshot");
	bounds_calls = ambient_calls = capget_calls = 0;
	capget_error = error;
	check(capng_get_caps_process() == -1, "capget failure was ignored");
	check(errno == error, "capget errno was lost");
	check(capget_calls == 1 && !bounds_calls && !ambient_calls,
	      "capget failure did not stop the snapshot read");
	check(capng_have_capabilities(CAPNG_SELECT_ALL) == CAPNG_FAIL,
	      "capget failure left a usable stale snapshot");
	check(!capng_have_capability(CAPNG_EFFECTIVE, CAP_CHOWN),
	      "capget failure exposed a stale capability");
	capget_error = 0;
	/* Restore a known-good state, as for bounding/ambient failures. */
	capng_restore_state(&saved);
	check(capng_get_caps_process() == 0, "Snapshot recovery failed");
}

static void test_capget_recovery(int error)
{
	int recovery;

	for (recovery = 0; recovery < 4; recovery++) {
		capng_clear(CAPNG_SELECT_ALL);
		capng_setpid(0);
		check(capng_get_caps_process() == 0,
		      "Initial recovery snapshot failed");
		capget_error = error;
		check(capng_get_caps_process() == -1 && errno == error,
		      "Expected capget failure before recovery");
		check(capng_have_capabilities(CAPNG_SELECT_ALL) == CAPNG_FAIL,
		      "Failed read exposed a usable snapshot");

		/* Recover without restoring saved state. Cover both direct
		 * retries and the clear/setpid sequence used by process scanners.
		 */
		if (recovery == 2)
			capng_clear(CAPNG_SELECT_ALL);
		if (recovery == 1 || recovery == 2) {
			capng_setpid(getpid() + 1);
			status_text = "CapBnd:\t0000000000000001\n"
				      "CapAmb:\t0000000000000001\n";
		} else if (recovery == 3) {
			/* Clearing only E/P/I must not revive stale Bnd or Amb. */
			capng_clear(CAPNG_SELECT_CAPS);
			check(capng_have_capabilities(CAPNG_SELECT_ALL) ==
			      CAPNG_NONE, "Partial clear revived stale sets");
		}
		capget_error = 0;
		capget_calls = 0;
		check(capng_get_caps_process() == 0 && capget_calls == 1,
		      "A failed capget prevented a fresh read");
		check(capget_pid == ((recovery == 1 || recovery == 2) ?
				    getpid() + 1 : 0),
		      "Recovery read used the wrong target PID");
		check(capng_have_capability(CAPNG_EFFECTIVE, CAP_CHOWN),
		      "Recovery did not install the fresh capabilities");
		status_text = NULL;
	}
	capng_setpid(0);
}

static void test_target(pid_t pid, const char *status, int expected_errno)
{
	void *saved = capng_save_state();
	int rc, read_errno;

	check(saved != NULL, "Failed to save state for target test");
	bounds_error = ambient_error = 0;
	status_text = status;
	capng_setpid(pid);
	bounds_calls = ambient_calls = 0;
	rc = capng_get_caps_process();
	read_errno = errno;
	if (expected_errno) {
		check(rc == -1 && read_errno == expected_errno,
		      "Remote metadata failure was not preserved");
		check(capng_have_capabilities(CAPNG_SELECT_ALL) == CAPNG_FAIL,
		      "Remote metadata failure left a usable snapshot");
	} else
		check(rc == 0, "Valid target snapshot was rejected");
	if (expected_errno || status)
		check(bounds_calls == 0 && ambient_calls == 0,
		      "Remote snapshot queried the caller's capabilities");
	else
		check(bounds_calls && ambient_calls,
		      "Self snapshot did not use prctl fallback");
	status_text = NULL;
	capng_restore_state(&saved);
}

#ifdef HAVE_SYSCALL_H
static void *test_thread_target(void *unused)
{
	(void)unused;
	capng_clear(CAPNG_SELECT_ALL);
	/* In a worker, the process leader's PID is not our own TID. */
	test_target(getpid(), NULL, ENOENT);
	test_target((pid_t)syscall(__NR_gettid), NULL, 0);
	test_target(0, NULL, 0);
	return NULL;
}
#endif

int main(void)
{
	/* Complete feature detection while every mocked query can succeed. */
	capng_clear(CAPNG_SELECT_ALL);
	test_read(0, 0, 0);
	test_read(EPERM, 0, EPERM);
	test_read(0, EACCES, EACCES);
	test_read(EPERM, EACCES, EPERM);
	test_capget_failure(ESRCH);
	test_capget_failure(EPERM);
	test_capget_recovery(ESRCH);
	test_capget_recovery(EPERM);
	test_target(0, NULL, 0);
	/* A nonzero target distinct from the caller, with mocked capget. */
	test_target(getpid() + 1, NULL, ENOENT);
	test_target(getpid() + 1, "Name:\ttarget\n", ENODATA);
	test_target(getpid() + 1, "CapBnd:\t0000000000000001\n", ENODATA);
	test_target(getpid() + 1, "CapBnd:\t0000000000000001\n"
		    "CapAmb:\t0000000000000001\n", 0);
#ifdef HAVE_SYSCALL_H
	pthread_t thread;

	test_target((pid_t)syscall(__NR_gettid), NULL, 0);
	check(pthread_create(&thread, NULL, test_thread_target, NULL) == 0,
	      "Failed to create target test thread");
	check(pthread_join(thread, NULL) == 0, "Failed to join test thread");
#endif
	puts("Process capability read error tests passed");
	return EXIT_SUCCESS;
}
#else
int main(void)
{
	return 77;
}
#endif
