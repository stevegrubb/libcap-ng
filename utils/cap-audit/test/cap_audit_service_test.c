// SPDX-License-Identifier: GPL-2.0-or-later
/* cap_audit_service_test.c -- service credential regression tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "cap_audit.h"

struct audit_state state;
int audit_machine;

static int change_id_calls;
static int changed_uid;
static int changed_gid;
static capng_flags_t changed_flags;

static void fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

const char *cap_name_safe(int cap)
{
	(void)cap;
	return "unknown";
}

int __wrap_capng_change_id(int uid, int gid, capng_flags_t flags)
{
	change_id_calls++;
	changed_uid = uid;
	changed_gid = gid;
	changed_flags = flags;
	return 0;
}

static char *write_service(const char *dir, const char *name,
			   const char *contents)
{
	char *path;
	size_t len = strlen(contents);
	ssize_t written;
	int fd;

	if (asprintf(&path, "%s/%s", dir, name) < 0)
		fail("Failed to allocate service path");
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		fail("Failed to open temporary service");
	written = write(fd, contents, len);
	close(fd);
	if (written < 0 || (size_t)written != len)
		fail("Failed to write temporary service");

	return path;
}

static int parse_unit(const char *dir, const char *name, const char *contents,
		      service_config_t *cfg)
{
	char *path;
	int rc;

	path = write_service(dir, name, contents);
	rc = parse_service_file(path, cfg);
	unlink(path);
	free(path);
	return rc;
}

static void expect_parse_failure(const char *dir, const char *name,
				 const char *contents)
{
	service_config_t cfg;

	if (parse_unit(dir, name, contents, &cfg) == 0) {
		free_config(&cfg);
		fail(name);
	}
}

static void test_dynamic_user(const char *dir)
{
	service_config_t cfg;
	const char unit[] =
		"[Service]\n"
		"DynamicUser=yes\n"
		"ExecStart=/usr/bin/true\n";

	if (parse_unit(dir, "dynamic.service", unit, &cfg) != 0)
		fail("DynamicUser service should parse");
	if (!cfg.user_resolved || !cfg.user_raw ||
	    strcmp(cfg.user_raw, "nobody") != 0)
		fail("DynamicUser should resolve to nobody for simulation");
	if (cfg.user_uid == 0 || cfg.user_uid > INT_MAX ||
	    cfg.user_primary_gid == 0 || cfg.user_primary_gid > INT_MAX)
		fail("DynamicUser simulation must use representable non-root IDs");

	change_id_calls = 0;
	if (apply_service_config(&cfg) != 0)
		fail("DynamicUser credentials should apply");
	if (change_id_calls != 1 || changed_uid != (int)cfg.user_uid ||
	    changed_gid != (int)cfg.user_primary_gid)
		fail("DynamicUser credentials did not reach capng_change_id");
	if (!(changed_flags & CAPNG_INIT_SUPP_GRP))
		fail("DynamicUser should initialize supplementary groups");

	free_config(&cfg);
}

static void test_unresolved_dynamic_user(const char *dir)
{
	service_config_t cfg;
	const char unit[] =
		"[Service]\n"
		"DynamicUser=yes\n"
		"User=cap-audit-no-such-user\n"
		"ExecStart=/usr/bin/true\n";

	if (parse_unit(dir, "dynamic-name.service", unit, &cfg) != 0)
		fail("Unresolved DynamicUser name should use the simulation user");
	if (!cfg.user_resolved || !cfg.user_raw ||
	    strcmp(cfg.user_raw, "nobody") != 0)
		fail("Unresolved DynamicUser name should map to nobody");
	free_config(&cfg);
}

static void test_valid_credentials(const char *dir)
{
	service_config_t cfg;
	const char unit[] =
		"[Service]\n"
		"User=0\n"
		"Group=0\n"
		"SupplementaryGroups=1 2\n"
		"ExecStart=/usr/bin/true\n";

	if (parse_unit(dir, "valid.service", unit, &cfg) != 0)
		fail("Valid numeric credentials should parse");
	if (!cfg.user_resolved || cfg.user_uid != 0 ||
	    !cfg.group_is_set || cfg.group_gid != 0 ||
	    cfg.sup_groups.count != 2)
		fail("Valid numeric credentials were not preserved");
	free_config(&cfg);
}

static void test_invalid_credentials(const char *dir)
{
	static const struct {
		const char *name;
		const char *unit;
	} tests[] = {
		{ "negative-user.service",
		  "[Service]\nUser=-1\nExecStart=/usr/bin/true\n" },
		{ "positive-user.service",
		  "[Service]\nUser=+1\nExecStart=/usr/bin/true\n" },
		{ "sentinel-user.service",
		  "[Service]\nUser=4294967295\nExecStart=/usr/bin/true\n" },
		{ "wrapped-user.service",
		  "[Service]\nUser=4294967296\nExecStart=/usr/bin/true\n" },
		{ "int-user.service",
		  "[Service]\nUser=2147483648\nExecStart=/usr/bin/true\n" },
		{ "legacy-user.service",
		  "[Service]\nUser=65535\nExecStart=/usr/bin/true\n" },
		{ "negative-group.service",
		  "[Service]\nGroup=-1\nExecStart=/usr/bin/true\n" },
		{ "wrapped-group.service",
		  "[Service]\nGroup=4294967296\nExecStart=/usr/bin/true\n" },
		{ "negative-supplementary.service",
		  "[Service]\nSupplementaryGroups=-1\nExecStart=/usr/bin/true\n" },
		{ "wrapped-supplementary.service",
		  "[Service]\nSupplementaryGroups=4294967296\nExecStart=/usr/bin/true\n" },
		{ "dynamic-negative-user.service",
		  "[Service]\nDynamicUser=yes\nUser=-1\n"
		  "ExecStart=/usr/bin/true\n" },
	};
	size_t i;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		expect_parse_failure(dir, tests[i].name, tests[i].unit);
}

static void test_sink_validation(void)
{
	service_config_t cfg = {
		.user_uid = (uid_t)UINT32_MAX,
		.user_primary_gid = (gid_t)UINT32_MAX,
		.user_is_set = true,
		.user_resolved = true,
	};

	change_id_calls = 0;
	if (apply_service_config(&cfg) == 0)
		fail("Unrepresentable credentials should fail before application");
	if (change_id_calls != 0)
		fail("Invalid credentials reached capng_change_id");
}

static void test_exec_start_privilege_prefixes(const char *dir)
{
	service_config_t cfg;
	const char bang_unit[] =
		"[Service]\n"
		"User=1234\n"
		"Group=1234\n"
		"SupplementaryGroups=1 2\n"
		"CapabilityBoundingSet=CAP_CHOWN\n"
		"NoNewPrivileges=yes\n"
		"ExecStart=-!/usr/bin/true\n";
	const char plus_unit[] =
		"[Service]\n"
		"ExecStart=-+/usr/bin/true\n";
	const char combined_plus_unit[] =
		"[Service]\n"
		"ExecStart=!-+/usr/bin/true\n";
	const char double_bang_unit[] =
		"[Service]\n"
		"ExecStart=!!/usr/bin/true\n";

	if (parse_unit(dir, "bang.service", bang_unit, &cfg) != 0)
		fail("ExecStart=! service should parse");
	if (!cfg.exec_start_no_setuid)
		fail("ExecStart=! credential semantics were not retained");
	if (!cfg.exec_argv || strcmp(cfg.exec_argv[0], "/usr/bin/true"))
		fail("ExecStart=! prefixes were not removed from executable");

	change_id_calls = 0;
	changed_uid = 0;
	changed_gid = 0;
	changed_flags = CAPNG_NO_FLAG;
	if (apply_service_config(&cfg) != 0)
		fail("ExecStart=! configuration should apply");
	if (change_id_calls != 1 || changed_uid != -1 || changed_gid != -1)
		fail("ExecStart=! must leave credential changes to the command");
	if (changed_flags & (CAPNG_INIT_SUPP_GRP |
			     CAPNG_APPLY_STAGED_GROUPS))
		fail("ExecStart=! must not apply supplementary groups");
	if (!(changed_flags & CAPNG_APPLY_BOUNDING))
		fail("ExecStart=! must still apply the capability bounding set");
	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		fail("ExecStart=! must still apply NoNewPrivileges");
	free_config(&cfg);

	expect_parse_failure(dir, "plus.service", plus_unit);
	expect_parse_failure(dir, "combined-plus.service", combined_plus_unit);
	expect_parse_failure(dir, "double-bang.service", double_bang_unit);
}

int main(void)
{
	char dir[] = "/tmp/libcap-ng-service-XXXXXX";

	if (mkdtemp(dir) == NULL)
		fail("Failed to create temporary directory");

	test_dynamic_user(dir);
	test_unresolved_dynamic_user(dir);
	test_valid_credentials(dir);
	test_invalid_credentials(dir);
	test_sink_validation();
	test_exec_start_privilege_prefixes(dir);

	rmdir(dir);
	puts("cap-audit service credential tests passed");
	return 0;
}
