// SPDX-License-Identifier: GPL-2.0-or-later
/* cap_audit_recommendation_test.c -- service recommendation tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cap_audit.h"

struct audit_state state;
int audit_machine;

static void fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

const char *cap_name_safe(int cap)
{
	switch (cap) {
	case CAP_CHOWN:
		return "chown";
	case CAP_DAC_OVERRIDE:
		return "dac_override";
	case CAP_FOWNER:
		return "fowner";
	case CAP_NET_BIND_SERVICE:
		return "net_bind_service";
	case CAP_SYS_CHROOT:
		return "sys_chroot";
	case CAP_SYS_ADMIN:
		return "sys_admin";
	default:
		return "unknown";
	}
}

const char *syscall_name_from_nr(int nr)
{
	(void)nr;
	return "openat";
}

int cap_required_union(const struct cap_check *check)
{
	return check->granted > 0 || check->op_granted > 0;
}

unsigned long cap_total_checks(const struct cap_check *check)
{
	return check->count + check->op_count;
}

unsigned long cap_total_granted(const struct cap_check *check)
{
	return check->granted + check->op_granted;
}

unsigned long cap_total_denied(const struct cap_check *check)
{
	return check->denied + check->op_denied;
}

const char *cap_union_reason(const struct cap_check *check)
{
	if (check->reason)
		return check->reason;
	return check->op_reason;
}

static char *capture_analysis(void)
{
	FILE *capture;
	char *output;
	long len;
	int saved_stdout;

	capture = tmpfile();
	if (!capture)
		fail("Failed to create output file");
	saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout < 0)
		fail("Failed to save stdout");
	if (fflush(stdout) || dup2(fileno(capture), STDOUT_FILENO) < 0)
		fail("Failed to capture stdout");

	analyze_capabilities();

	if (fflush(stdout) || dup2(saved_stdout, STDOUT_FILENO) < 0)
		fail("Failed to restore stdout");
	close(saved_stdout);
	if (fseek(capture, 0, SEEK_END) != 0)
		fail("Failed to seek captured output");
	len = ftell(capture);
	if (len < 0 || fseek(capture, 0, SEEK_SET) != 0)
		fail("Failed to measure captured output");
	output = malloc((size_t)len + 1);
	if (!output)
		fail("Failed to allocate captured output");
	if (fread(output, 1, (size_t)len, capture) != (size_t)len)
		fail("Failed to read captured output");
	output[len] = '\0';
	fclose(capture);

	return output;
}

static void expect_line(const char *output, const char *line)
{
	const char *found = strstr(output, line);
	size_t len = strlen(line);

	if (!found || found[len] != '\n')
		fail(line);
}

static int contains_tokens(const char *output, const char *const *tokens,
			   size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		output = strstr(output, tokens[i]);
		if (!output)
			return 0;
		output += strlen(tokens[i]);
	}

	return 1;
}

static void setup_analysis(service_config_t *service)
{
	static int denied_syscall = 257;
	struct cap_check *check;

	memset(&state, 0, sizeof(state));
	memset(service, 0, sizeof(*service));
	state.app.exe = "/usr/bin/recommendation-target";
	state.app.pid = 1234;
	state.app.prog_type = ELF;
	strcpy(state.app.kernel_version, "validation");
	state.service_file = "/tmp/recommendation.service";
	state.service_cfg = service;
	state.capset_observed = 1;

	service->user_raw = "validation-user";
	service->user_uid = 1000;
	service->user_primary_gid = 1000;
	service->user_is_set = true;
	service->user_resolved = true;
	service->exec_start = "/usr/bin/recommendation-target";
	service->bounding.seen = true;
	service->bounding.caps[CAP_SYS_ADMIN] = true;

	check = &state.app.checks[CAP_CHOWN];
	check->count = 1;
	check->denied = 1;
	check->denied_syscalls = &denied_syscall;
	check->denied_syscall_count = 1;

	check = &state.app.checks[CAP_DAC_OVERRIDE];
	check->count = 1;
	check->granted = 1;

	check = &state.app.checks[CAP_FOWNER];
	check->count = 2;
	check->granted = 1;
	check->denied = 1;

	check = &state.app.checks[CAP_NET_BIND_SERVICE];
	check->count = 1;
	check->granted = 1;

	check = &state.app.checks[CAP_SYS_CHROOT];
	check->op_count = 1;
	check->op_granted = 1;
}

int main(void)
{
	static const char *const denied_guidance[] = {
		"Detailed evidence appears in",
		"CAPABILITIES WITH NO GRANTED CHECKS",
		"No",
		"capability in that section",
		"added",
		"automatically",
		"confirming",
		"required functionality",
		"fails",
		"absent",
	};
	service_config_t service;
	char *output;

	setup_analysis(&service);
	output = capture_analysis();

	expect_line(output,
		    "    AmbientCapabilities=dac_override fowner "
		    "net_bind_service sys_chroot");
	expect_line(output,
		    "    CapabilityBoundingSet=dac_override fowner "
		    "net_bind_service sys_chroot");
	expect_line(output,
		    "    Initialization capabilities: dac_override fowner "
		    "net_bind_service");
	expect_line(output,
		    "    Operational capabilities: sys_chroot");

	if (!strstr(output, "chown: Additional evidence required") ||
	    !strstr(output, "Capability is absent from the configured"))
		fail("Denied-only capability was hidden from diagnostics");
	if (!contains_tokens(output, denied_guidance,
			     sizeof(denied_guidance) /
			     sizeof(denied_guidance[0])))
		fail("Denied-only capability lacked investigation guidance");
	if (!strstr(output, "Configured but not observed: sys_admin"))
		fail("Unused bounding capability was not reported as removable");
	if (!strstr(output, "Consider removing from CapabilityBoundingSet"))
		fail("Unused bounding capability lacked removal guidance");

	free(output);
	puts("cap-audit service recommendation tests passed");
	return 0;
}
