// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise filecap's real path handling and output without file privileges.
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */
#define main filecap_main
#include "../filecap.c"
#undef main
#include "proc-sanitize.h"
#include <limits.h>
#include <sys/wait.h>

enum {
	EFFECTIVE_CAPS, PERMITTED_CAPS, FULL_CAPS, NO_CAPS, READ_ERROR,
};
static int fixture;
static int allocation_failure;

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}

/* Keep the library's real capability queries and formatting deterministic. */
int __wrap_capng_get_caps_fd(int fd)
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

int __wrap_capng_apply_caps_fd(int fd)
{
	(void)fd;
	errno = EPERM;
	return -1;
}

char *__real_sanitize_untrusted_field(const char *path);

/* Allocation can change errno; path diagnostics must retain the real error. */
char *__wrap_sanitize_untrusted_field(const char *path)
{
	char *safe = allocation_failure ? NULL :
		__real_sanitize_untrusted_field(path);

	errno = allocation_failure ? ENOMEM : EDOM;
	return safe;
}

static void check_output(FILE *file, const char *expected)
{
	char output[4096];
	size_t len;

	rewind(file);
	len = fread(output, 1, sizeof(output) - 1, file);
	output[len] = '\0';
	if (ferror(file) || fgetc(file) != EOF || strcmp(output, expected))
		fail("Unexpected filecap output");
	fclose(file);
}

/* Isolate main's globals and exit paths, and capture both output streams. */
static void run_filecap(char **args, const char *output, const char *errors,
			int expected_status)
{
	FILE *out = tmpfile(), *err = tmpfile();
	int argc = 0, status;
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
		    dup2(fileno(err), STDERR_FILENO) < 0)
			_exit(EXIT_FAILURE);
		exit(filecap_main(argc, args));
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != expected_status)
		fail("Unexpected filecap exit status");
	check_output(out, output);
	check_output(err, errors);
}

int main(void)
{
	static const struct {
		const char *name, *safe;
	} names[] = {
		{ "crafted\n\r\t\033[2J\177", "crafted\\x0A\\x0D\\x09\\x1B[2J\\x7F" },
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
