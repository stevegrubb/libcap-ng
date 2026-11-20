// SPDX-License-Identifier: GPL-2.0-or-later
/* cap_audit_path_test.c -- target PATH resolution regression tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "cap_audit_path.h"

enum confstr_mode {
	CONFSTR_REAL,
	CONFSTR_DEFAULT_PATH,
	CONFSTR_FAILURE,
	CONFSTR_TRUNCATED,
};

static enum confstr_mode confstr_mode;
static const char *default_path;
static unsigned int confstr_calls;

size_t __real_confstr(int name, char *buf, size_t size);

size_t __wrap_confstr(int name, char *buf, size_t size)
{
	if (name == _CS_PATH)
		confstr_calls++;
	if (name != _CS_PATH || confstr_mode == CONFSTR_REAL)
		return __real_confstr(name, buf, size);
	if (confstr_mode == CONFSTR_FAILURE)
		return 0;

	/* Keep the default executable in a temporary, test-owned directory. */
	snprintf(buf, size, "%s", default_path);
	if (confstr_mode == CONFSTR_TRUNCATED)
		return size + 1;
	return strlen(default_path) + 1;
}

static void fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

static void make_executable(const char *path)
{
	int fd;
	const char script[] = "#!/bin/sh\nexit 0\n";
	ssize_t rc;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (fd < 0)
		fail("Failed to create executable target");
	rc = write(fd, script, sizeof(script) - 1);
	close(fd);
	if (rc != (ssize_t)(sizeof(script) - 1))
		fail("Failed to write executable target");
}

static void check_resolved(const char *target, const char *expected)
{
	char *resolved = resolve_target_command(target);

	if ((expected && (!resolved || strcmp(resolved, expected))) ||
	    (!expected && resolved)) {
		fprintf(stderr, "Unexpected resolution of %s: %s\n", target,
			resolved ? resolved : "(rejected)");
		exit(EXIT_FAILURE);
	}
	free(resolved);
}

static void test_path_fallback(const char *root, const char *late,
			       const char *late_target)
{
	const char *paths[] = { "", ":missing", "missing:", "missing::other" };
	char local_target[PATH_MAX];
	int cwd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	size_t i;

	if (cwd < 0 || chdir(root) != 0 ||
	    snprintf(local_target, sizeof(local_target), "%s/probe", root) < 0)
		fail("Failed to prepare current-directory target");
	make_executable(local_target);
	confstr_mode = CONFSTR_DEFAULT_PATH;
	default_path = late;
	confstr_calls = 0;
	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (setenv("PATH", paths[i], 1))
			fail("Failed to set current-directory PATH");
		check_resolved("probe", "./probe");
		check_resolved(local_target, local_target);
		check_resolved("./probe", "./probe");
	}
	if (confstr_calls)
		fail("Set PATH unexpectedly queried the default path");

	if (unsetenv("PATH"))
		fail("Failed to unset PATH");
	check_resolved("probe", late_target);
	if (confstr_calls != 1)
		fail("Unset PATH did not query the default path once");
	confstr_mode = CONFSTR_FAILURE;
	check_resolved("probe", NULL);
	confstr_mode = CONFSTR_TRUNCATED;
	check_resolved("probe", NULL);
	/* Explicit pathnames bypass the default, including a failed query. */
	confstr_mode = CONFSTR_FAILURE;
	confstr_calls = 0;
	check_resolved(local_target, local_target);
	check_resolved("./probe", "./probe");
	if (confstr_calls)
		fail("Explicit pathname unexpectedly queried the default path");
	confstr_mode = CONFSTR_REAL;
	if (unlink(local_target) || fchdir(cwd) || close(cwd))
		fail("Failed to restore the working directory");
}

static void test_native_default(void)
{
	char *args[] = { "sh", "-c", "exit 0", NULL };
	char *resolved;
	pid_t child;
	int status;

	if (unsetenv("PATH"))
		fail("Failed to unset PATH for native execution");
	resolved = resolve_target_command(args[0]);
	if (!resolved)
		fail("Default path did not resolve the system shell");
	free(resolved);
	child = fork();
	if (child < 0)
		fail("Failed to fork native execvp test");
	if (child == 0) {
		execvp(args[0], args);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		fail("Native execvp default could not execute the system shell");
}

int main(void)
{
	char root[] = "/tmp/libcap-ng-cap-audit-path-XXXXXX";
	char early[PATH_MAX];
	char late[PATH_MAX];
	char early_target[PATH_MAX];
	char late_target[PATH_MAX];
	char link_target[PATH_MAX];
	char path[PATH_MAX * 2 + 2];
	char *resolved;

	if (!mkdtemp(root))
		fail("Failed to create temporary directory");
	if (snprintf(early, sizeof(early), "%s/early", root) < 0 ||
	    snprintf(late, sizeof(late), "%s/late", root) < 0 ||
	    snprintf(early_target, sizeof(early_target), "%s/probe",
		     early) < 0 ||
	    snprintf(late_target, sizeof(late_target), "%s/probe", late) < 0 ||
	    snprintf(link_target, sizeof(link_target), "%s/link", root) < 0)
		fail("Failed to format target paths");
	if (mkdir(early, 0700) || mkdir(late, 0700) ||
	    mkdir(early_target, 0700))
		fail("Failed to create PATH directories");
	make_executable(late_target);

	if (snprintf(path, sizeof(path), "%s:%s", early, late) < 0 ||
	    setenv("PATH", path, 1))
		fail("Failed to set test PATH");
	resolved = resolve_target_command("probe");
	if (!resolved || strcmp(resolved, late_target))
		fail("Resolver did not skip a directory PATH candidate");
	free(resolved);

	resolved = resolve_target_command(early_target);
	if (resolved)
		fail("Resolver accepted a directory target");

	resolved = resolve_target_command(late_target);
	if (!resolved || strcmp(resolved, late_target))
		fail("Resolver rejected a regular executable");
	free(resolved);

	if (symlink(late_target, link_target))
		fail("Failed to create executable symlink");
	resolved = resolve_target_command(link_target);
	if (!resolved || strcmp(resolved, link_target))
		fail("Resolver rejected a symlink to an executable");
	free(resolved);
	test_path_fallback(root, late, late_target);
	test_native_default();
	if (unlink(link_target) || unlink(late_target) ||
	    rmdir(early_target) || rmdir(early) || rmdir(late) || rmdir(root))
		fail("Failed to remove temporary paths");

	puts("cap-audit target PATH tests passed");
	return 0;
}
