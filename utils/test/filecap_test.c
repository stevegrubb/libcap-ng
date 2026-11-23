// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise filecap's real path handling and output without file privileges.
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */
#include "config.h"
#include "cap-ng.h"
#include "proc-sanitize.h"

static int fixture_get_caps_fd(int fd);
static int fixture_apply_caps_fd(int fd);
static int fixture_update(capng_act_t action, capng_type_t type,
			  unsigned int cap);
static char *fixture_sanitize(const char *path);

/*
 * Redirect calls in filecap.c explicitly: LTO can bind or inline the real
 * sanitizer before the linker has a chance to apply --wrap replacements.
 */
#define main filecap_main
#define capng_get_caps_fd fixture_get_caps_fd
#define capng_apply_caps_fd fixture_apply_caps_fd
#define capng_update fixture_update
#define sanitize_untrusted_field fixture_sanitize
#include "../filecap.c"
#undef sanitize_untrusted_field
#undef capng_apply_caps_fd
#undef capng_update
#undef capng_get_caps_fd
#undef main
#include <limits.h>
#include <sys/wait.h>

enum {
	EFFECTIVE_CAPS, PERMITTED_CAPS, FULL_CAPS, NO_CAPS, READ_ERROR,
};
static int fixture;
static int allocation_failure;
static int reject_update;
static const char *const fixture_names[] = {
	"effective", "permitted", "full", "no capabilities", "read error",
};

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}

/* Keep the library's real capability queries and formatting deterministic. */
static int fixture_get_caps_fd(int fd)
{
	capng_type_t type = CAPNG_PERMITTED;

	(void)fd;
	if (fixture == READ_ERROR || fixture == NO_CAPS) {
		errno = fixture == READ_ERROR ? EIO : ENODATA;
		return -1;
	}
	if (fixture == FULL_CAPS)
		capng_fill(CAPNG_SELECT_CAPS);
	else {
		if (fixture == EFFECTIVE_CAPS)
			type |= CAPNG_EFFECTIVE;
		if (capng_update(CAPNG_ADD, type, CAP_CHOWN))
			fail("Cannot stage file capability fixture");
	}
	return 0;
}

static int fixture_apply_caps_fd(int fd)
{
	(void)fd;
	if (reject_update)
		fail("Filecap reached the xattr writer after staging failed");
	errno = EPERM;
	return -1;
}

/* Simulate newer build headers than the running kernel supports. */
static int fixture_update(capng_act_t action, capng_type_t type,
			  unsigned int cap)
{
	if (reject_update && cap == CAP_SYS_ADMIN) {
		errno = EINVAL;
		return -1;
	}
	return capng_update(action, type, cap);
}

/* Allocation can change errno; path diagnostics must retain the real error. */
static char *fixture_sanitize(const char *path)
{
	char *safe = allocation_failure ? NULL :
		sanitize_untrusted_field(path);

	errno = allocation_failure ? ENOMEM : EDOM;
	return safe;
}

static int check_output(FILE *file, const char *expected, const char *stream,
			int show)
{
	char output[4096];
	char *safe_expected, *safe_output;
	size_t len, offset;
	int failed;

	rewind(file);
	len = fread(output, 1, sizeof(output) - 1, file);
	output[len] = '\0';
	failed = ferror(file) || fgetc(file) != EOF || strcmp(output, expected);
	if (failed || show) {
		if (strcmp(output, expected)) {
			for (offset = 0; output[offset] && expected[offset] &&
			     output[offset] == expected[offset]; offset++)
				;
			fprintf(stderr, "%s first mismatch at byte %zu: "
				"expected 0x%02X, actual 0x%02X\n", stream,
				offset, (unsigned char)expected[offset],
				(unsigned char)output[offset]);
		}
		safe_expected = sanitize_untrusted_field(expected);
		safe_output = sanitize_untrusted_field(output);
		fprintf(stderr, "%s expected (%zu bytes): %s\n", stream,
			strlen(expected),
			safe_expected ? safe_expected : "[unavailable]");
		fprintf(stderr, "%s actual (%zu captured bytes): %s\n", stream,
			len, safe_output ? safe_output : "[unavailable]");
		free(safe_expected);
		free(safe_output);
	}
	fclose(file);
	return failed;
}

static void describe_case(char **args)
{
	int i;

	fprintf(stderr, "filecap_test: fixture=%s allocation_failure=%d\n",
		fixture_names[fixture], allocation_failure);
	for (i = 0; args[i]; i++) {
		char *safe = sanitize_untrusted_field(args[i]);

		fprintf(stderr, "  argv[%d]: %s\n", i,
			safe ? safe : "[unavailable]");
		free(safe);
	}
}

/* Isolate main's globals and exit paths, and capture both output streams. */
static void run_filecap(char **args, const char *output, const char *errors,
			int expected_status)
{
	FILE *out = tmpfile(), *err = tmpfile();
	int argc = 0, status, failed, out_failed, err_failed;
	pid_t child;

	while (args[argc])
		argc++;
	if (!out || !err || fflush(NULL))
		fail("Cannot prepare filecap output capture");
	child = fork();
	if (child < 0)
		fail("Cannot fork filecap test");
	if (child == 0) {
		if (dup2(fileno(out), STDOUT_FILENO) < 0 ||
		    dup2(fileno(err), STDERR_FILENO) < 0) {
			perror("Cannot redirect filecap output");
			_exit(EXIT_FAILURE);
		}
		exit(filecap_main(argc, args));
	}
	if (waitpid(child, &status, 0) != child) {
		perror("Cannot wait for filecap test");
		fail("Cannot collect filecap exit status");
	}
	failed = !WIFEXITED(status) || WEXITSTATUS(status) != expected_status;
	if (failed) {
		describe_case(args);
		if (WIFEXITED(status))
			fprintf(stderr, "Exit status: expected %d, actual %d\n",
				expected_status, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			fprintf(stderr, "Expected exit %d, killed by signal %d\n",
				expected_status, WTERMSIG(status));
	}
	/* Always inspect both streams, especially after a child failure. */
	out_failed = check_output(out, output, "stdout", failed);
	err_failed = check_output(err, errors, "stderr", failed);
	if (failed || out_failed || err_failed) {
		if (!failed)
			describe_case(args);
		fail("Filecap test case failed");
	}
}

int main(void)
{
	static const struct {
		const char *name, *safe;
	} names[] = {
		{ "crafted\n\r\t\033[2J\177", "crafted\\x0A\\x0D\\x09\\x1B[2J\\x7F" },
		{ "c1-\2332J", "c1-\\x9B2J" },
		{ "unicode-c1-\302\2332J", "unicode-c1-\\xC2\\x9B2J" },
		/* Escape the whole character rather than split it at byte 0x9B. */
		{ "utf8-continuation-\303\233",
		  "utf8-continuation-\\xC3\\x9B" },
		{ "ordinary", "ordinary" },
		{ "literal\\x1B-é", "literal\\x1B-é" },
	};
	static const char *const sets[] = {
		"effective", "permitted", "effective",
	};
	char directory[] = "filecap-test.XXXXXX";
	char path[PATH_MAX], safe[PATH_MAX], output[4096], errors[4096];
	char *args[] = { "filecap", path, NULL, NULL };
	char *absolute;
	size_t i;
	int fd;

	if (!mkdtemp(directory) || !(absolute = realpath(directory, NULL)))
		fail("Cannot create filecap fixture directory");
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", absolute, names[i].name);
		snprintf(safe, sizeof(safe), "%s/%s", absolute, names[i].safe);
		fd = open(path, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600);
		if (fd < 0 || close(fd))
			fail("Cannot create filecap fixture");
		for (fixture = EFFECTIVE_CAPS; fixture <= FULL_CAPS; fixture++) {
			snprintf(output, sizeof(output),
				 "%-9s %-22s capabilities  rootid\n%s %-22s %s\n",
				 "set", "file", sets[fixture], safe,
				 fixture == FULL_CAPS ? "full" : "chown");
			run_filecap(args, output, "", 0);
		}
		fixture = NO_CAPS;
		run_filecap(args, "", "", 0);
		fixture = READ_ERROR;
		snprintf(errors, sizeof(errors),
			 "Unable to get capabilities of %s: %s\n", safe,
			 strerror(EIO));
		run_filecap(args, "", errors, 1);

		fixture = EFFECTIVE_CAPS;
		args[2] = "chown";
		snprintf(errors, sizeof(errors),
			 "Could not set capabilities on %s: %s\n", safe,
			 strerror(EPERM));
		run_filecap(args, "", errors, 1);
		args[2] = NULL;

		reject_update = 1;
		snprintf(errors, sizeof(errors),
			 "Could not stage capability for %s: %s\n", safe,
			 strerror(EINVAL));
		/* Reject both an empty and a partially staged replacement.
		 * In each case the writer must remain unreachable.
		 */
		run_filecap((char *[]) { "filecap", path, "sys_admin", NULL },
			    "", errors, 1);
		run_filecap((char *[]) { "filecap", path, "chown",
					"sys_admin", NULL }, "", errors, 1);
		run_filecap((char *[]) { "filecap", path, "none",
					"sys_admin", NULL }, "", errors, 1);
		reject_update = 0;

		/* Recursive scans use the same callback with single_file unset. */
		args[1] = absolute;
		snprintf(output, sizeof(output),
			 "%-9s %-22s capabilities  rootid\neffective %-22s chown\n",
			 "set", "file", safe);
		run_filecap(args, output, "", 0);
		args[1] = path;

		allocation_failure = 1;
		run_filecap(args, "", "Out of memory\n", 1);
		allocation_failure = 0;
		if (unlink(path))
			fail("Cannot remove filecap fixture");
		snprintf(errors, sizeof(errors), "Error checking path %s: %s\n",
			 safe, strerror(ENOENT));
		run_filecap(args, "", errors, 1);
	}
	free(absolute);
	if (rmdir(directory))
		fail("Cannot remove filecap fixture directory");
	return EXIT_SUCCESS;
}
