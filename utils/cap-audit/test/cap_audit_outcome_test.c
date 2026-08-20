// SPDX-License-Identifier: GPL-2.0-or-later
/* cap_audit_outcome_test.c -- syscall outcome correlation tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cap_audit.h"

#define TEST_MOUNT_NR		1001
#define TEST_IOCTL_NR		1002
#define TEST_PROCESS_VM_NR	1003
#define TEST_OPENAT_NR		1004
#define TEST_BIND_NR		1005
#define TEST_LINK_NR		1006
#define TEST_KILL_NR		1007
#define TEST_ACCESS_NR		1008
#define TEST_ERESTARTSYS	512

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
	case CAP_DAC_READ_SEARCH:
		return "dac_read_search";
	case CAP_FOWNER:
		return "fowner";
	case CAP_KILL:
		return "kill";
	case CAP_NET_BIND_SERVICE:
		return "net_bind_service";
	case CAP_SYS_PTRACE:
		return "sys_ptrace";
	case CAP_SYS_ADMIN:
		return "sys_admin";
	case CAP_SYS_RESOURCE:
		return "sys_resource";
	default:
		return "unknown";
	}
}

const char *syscall_name_from_nr(int nr)
{
	switch (nr) {
	case TEST_MOUNT_NR:
		return "mount";
	case TEST_IOCTL_NR:
		return "ioctl";
	case TEST_PROCESS_VM_NR:
		return "process_vm_readv";
	case TEST_OPENAT_NR:
		return "openat";
	case TEST_BIND_NR:
		return "bind";
	case TEST_LINK_NR:
		return "link";
	case TEST_KILL_NR:
		return "kill";
	case TEST_ACCESS_NR:
		return "access";
	default:
		return NULL;
	}
}

char *json_escape(const char *input)
{
	return input ? strdup(input) : strdup("");
}

void update_reason(struct cap_check *check, int syscall_nr)
{
	const char *name = syscall_name_from_nr(syscall_nr);

	if (asprintf(&check->reason, "Used by %s", name ? name : "unknown") < 0)
		check->reason = NULL;
}

void update_reason_op(struct cap_check *check, int syscall_nr)
{
	(void)check;
	(void)syscall_nr;
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

static void emit_check(int cap, int syscall_nr, int result)
{
	struct cap_event event = {
		.pid = 1234,
		.tid = 1234,
		.capability = cap,
		.result = result,
		.syscall_nr = syscall_nr,
		.event_type = CAP_EVENT_CHECK,
	};

	if (handle_cap_event(NULL, &event, sizeof(event)) != 0)
		fail("Capability event was rejected");
}

static void emit_outcome(int cap, int syscall_nr, __s64 result)
{
	struct cap_event event = {
		.pid = 1234,
		.tid = 1234,
		.syscall_nr = syscall_nr,
		.syscall_ret = result,
		.denied_caps = 1ULL << cap,
		.event_type = CAP_EVENT_SYSCALL_RESULT,
	};

	if (handle_cap_event(NULL, &event, sizeof(event)) != 0)
		fail("Syscall outcome event was rejected");
}

static void emit_capset(__s64 result, __u64 effective, __u64 permitted,
			__u64 inheritable)
{
	struct cap_event event = {
		.pid = 1235,
		.tid = 1235,
		.syscall_ret = result,
		.capset_effective = effective,
		.capset_permitted = permitted,
		.capset_inheritable = inheritable,
		.event_type = CAP_EVENT_CAPSET,
	};

	if (handle_cap_event(NULL, &event, sizeof(event)) != 0)
		fail("capset event was rejected");
}

static void setup_events(void)
{
	int i;

	memset(&state, 0, sizeof(state));
	state.app.exe = "/usr/bin/outcome-target";
	state.app.pid = 1234;
	state.app.prog_type = ELF;
	strcpy(state.app.kernel_version, "validation");

	emit_check(CAP_NET_BIND_SERVICE, TEST_BIND_NR, 1);

	emit_check(CAP_SYS_ADMIN, TEST_MOUNT_NR, 0);
	emit_outcome(CAP_SYS_ADMIN, TEST_MOUNT_NR, -EPERM);
	emit_check(CAP_SYS_ADMIN, TEST_MOUNT_NR, 0);
	emit_outcome(CAP_SYS_ADMIN, TEST_MOUNT_NR, 0);
	emit_check(CAP_SYS_ADMIN, TEST_MOUNT_NR, 0);
	emit_outcome(CAP_SYS_ADMIN, TEST_MOUNT_NR, -ENOENT);

	emit_check(CAP_DAC_OVERRIDE, TEST_IOCTL_NR, 0);
#ifdef EBADFD
	emit_outcome(CAP_DAC_OVERRIDE, TEST_IOCTL_NR, -EBADFD);
#else
	emit_outcome(CAP_DAC_OVERRIDE, TEST_IOCTL_NR, -EBADF);
#endif

	for (i = 0; i < 3; i++) {
		emit_check(CAP_FOWNER, TEST_LINK_NR, 0);
		emit_outcome(CAP_FOWNER, TEST_LINK_NR, 0);
	}
	for (i = 0; i < 2; i++) {
		emit_check(CAP_DAC_READ_SEARCH, TEST_ACCESS_NR, 0);
		emit_outcome(CAP_DAC_READ_SEARCH, TEST_ACCESS_NR, 0);
	}
	emit_check(CAP_DAC_READ_SEARCH, TEST_ACCESS_NR, 0);
	emit_outcome(CAP_DAC_READ_SEARCH, TEST_ACCESS_NR, -ENOENT);

	emit_check(CAP_KILL, TEST_KILL_NR, 0);
	emit_outcome(CAP_KILL, TEST_KILL_NR, -EINTR);
	emit_check(CAP_KILL, TEST_KILL_NR, 0);
	emit_outcome(CAP_KILL, TEST_KILL_NR, -TEST_ERESTARTSYS);

	for (i = 0; i < 20; i++) {
		emit_check(CAP_SYS_PTRACE, TEST_PROCESS_VM_NR, 0);
		emit_outcome(CAP_SYS_PTRACE, TEST_PROCESS_VM_NR, 0);
	}
	emit_check(CAP_SYS_PTRACE, TEST_PROCESS_VM_NR, 0);
	emit_outcome(CAP_SYS_PTRACE, TEST_PROCESS_VM_NR, -EINTR);

	/* A success correlated to another capability must not count here. */
	emit_check(CAP_NET_BIND_SERVICE, TEST_OPENAT_NR, 0);
	emit_outcome(CAP_NET_BIND_SERVICE, TEST_OPENAT_NR, 0);
	emit_check(CAP_CHOWN, TEST_OPENAT_NR, 0);

	/* Failed capset payloads are diagnostic noise, not compatibility input. */
	emit_capset(-EPERM, 1ULL << CAP_SYS_CHROOT,
		    1ULL << CAP_SYS_CHROOT, 0);
	emit_capset(0, (1ULL << CAP_NET_BIND_SERVICE) |
		       (1ULL << CAP_SYS_RESOURCE),
		    (1ULL << CAP_NET_BIND_SERVICE) |
		       (1ULL << CAP_SYS_RESOURCE), 0);
}

typedef void (*output_fn)(void);

static char *capture_output(output_fn output)
{
	FILE *capture;
	char *text;
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

	output();

	if (fflush(stdout) || dup2(saved_stdout, STDOUT_FILENO) < 0)
		fail("Failed to restore stdout");
	close(saved_stdout);
	if (fseek(capture, 0, SEEK_END) != 0)
		fail("Failed to seek captured output");
	len = ftell(capture);
	if (len < 0 || fseek(capture, 0, SEEK_SET) != 0)
		fail("Failed to measure captured output");
	text = malloc((size_t)len + 1);
	if (!text)
		fail("Failed to allocate captured output");
	if (fread(text, 1, (size_t)len, capture) != (size_t)len)
		fail("Failed to read captured output");
	text[len] = '\0';
	fclose(capture);

	return text;
}

static void expect_text(const char *output, const char *expected)
{
	if (!strstr(output, expected))
		fail(expected);
}

static size_t count_text(const char *output, const char *expected)
{
	size_t count = 0;
	size_t len = strlen(expected);

	while ((output = strstr(output, expected)) != NULL) {
		count++;
		output += len;
	}
	return count;
}

static void test_human_output(void)
{
	service_config_t service = {
		.user_raw = "validation-user",
		.user_uid = 1000,
		.user_primary_gid = 1000,
		.user_is_set = true,
		.user_resolved = true,
		.exec_start = "/usr/bin/outcome-target",
		.bounding = {
			.seen = true,
		},
	};
	char *output;

	output = capture_output(analyze_capabilities);
	expect_text(output, "mount: 1 failed with -EPERM");
	expect_text(output, "mount: 1 failed with -ENOENT");
#ifdef EBADFD
	expect_text(output, "ioctl: 1 failed with -EBADFD");
#else
	expect_text(output, "ioctl: 1 failed with -EBADF");
#endif
	expect_text(output, "process_vm_readv: 20 succeeded");
	expect_text(output, "process_vm_readv: 1 interrupted with -EINTR");
	expect_text(output, "link: 3 succeeded");
	expect_text(output, "access: 2 succeeded");
	expect_text(output, "access: 1 failed with -ENOENT");
	expect_text(output, "kill: 1 interrupted with -EINTR");
	expect_text(output, "kill: 1 interrupted with -ERESTARTSYS");
	expect_text(output, "CAPSET-ONLY CAPABILITIES:");
	expect_text(output, "sys_resource (#24)");
	expect_text(output,
		    "Requested by successful capset in: effective, permitted");
	expect_text(output, "compatibility constraint");
	expect_text(output, "confirmed");
	expect_text(output, "functional use");
	expect_text(output, "Successful capset calls: 1");
	expect_text(output, "Capset-only capabilities: 1");
	expect_text(output, "CAPABILITIES WITH ONLY NOT-GRANTED CHECKS:");
	expect_text(output, "Capability checks returning not granted: 1");
	expect_text(output,
		    "Outcomes of syscall invocations containing such a check:");
	expect_text(output, "Associated syscall invocations:");
	expect_text(output, "Failure categories:");
	expect_text(output, "sys_admin: Manual investigation required");
	expect_text(output, "sys_ptrace: Manual investigation required");
	expect_text(output, "chown: Additional evidence required");
	expect_text(output, "openat: outcome unavailable");
	expect_text(output, "kill: Additional evidence required");
	expect_text(output, "fowner: Omitted; associated syscalls succeeded");
	expect_text(output,
		    "dac_read_search: Omitted; successes and non-permission "
		    "failures observed");
	expect_text(output,
		    "Associated syscall invocations: 2 succeeded and 1 failed");
	expect_text(output, "non-permission reasons");
	expect_text(output,
		    "not-granted capability checks are not established");
	expect_text(output, "cause of those failures");
	expect_text(output, "Manual investigation required: 2");
	expect_text(output, "Additional evidence required: 2");
	expect_text(output, "Omitted after associated syscall success: 1");
	expect_text(output,
		    "Omitted after mixed success/non-permission failure: 1");
	expect_text(output, "Capability check not established as cause: 1");
	expect_text(output,
		    "CapabilityBoundingSet=net_bind_service sys_resource");
	free(output);

	service.bounding.caps[CAP_NET_BIND_SERVICE] = true;
	state.service_file = "/tmp/outcome.service";
	state.service_cfg = &service;
	output = capture_output(analyze_capabilities);
	expect_text(output, "sys_admin: Manual investigation required");
	expect_text(output, "Capability is absent from the configured");
	expect_text(output, "Mixed capability-check results: net_bind_service");
	expect_text(output,
		    "Capset-only compatibility capabilities: sys_resource");
	expect_text(output, "sys_resource is absent from the configured");
	expect_text(output,
		    "Detailed evidence appears in CAPABILITIES WITH ONLY");
	if (count_text(output, "mount: 1 failed with -EPERM") != 1 ||
	    count_text(output, "mount: 1 failed with -ENOENT") != 1)
		fail("Service recommendations duplicated syscall outcomes");
	expect_text(output,
		    "CapabilityBoundingSet=net_bind_service sys_resource");
	free(output);
	state.service_cfg = NULL;
}

static void test_structured_output(void)
{
	char *output;

	output = capture_output(output_json);
	expect_text(output, "\"assessment\": \"permission_failure\"");
	expect_text(output, "\"assessment\": \"mixed_success_interruption\"");
	expect_text(output,
		    "\"assessment\": \"mixed_success_other_failure\"");
	expect_text(output, "\"assessment\": \"denial_not_established\"");
	expect_text(output, "\"assessment\": \"inconclusive\"");
	expect_text(output, "\"assessment\": \"succeeded_despite_denial\"");
	expect_text(output, "\"return_name\": \"EPERM\"");
	expect_text(output, "\"return_name\": \"ENOENT\"");
	expect_text(output, "\"not_granted_checks\": 1");
	expect_text(output, "\"successful_capset_calls\": 1");
	expect_text(output, "\"capset_only_capabilities\": [");
	expect_text(output, "\"name\": \"sys_resource\"");
	expect_text(output,
		    "\"requested_sets\": [\"effective\", \"permitted\"]");
	expect_text(output, "\"denied_syscalls\": [");
	expect_text(output, "\"return_name\": \"ERESTARTSYS\",\n"
		    "          \"errno\": null");
#ifdef EBADFD
	expect_text(output, "\"return_name\": \"EBADFD\"");
#endif
	expect_text(output, "\"count\": 20");
	free(output);

	output = capture_output(output_yaml);
	expect_text(output, "assessment: permission_failure");
	expect_text(output, "assessment: mixed_success_interruption");
	expect_text(output, "assessment: mixed_success_other_failure");
	expect_text(output, "assessment: denial_not_established");
	expect_text(output, "assessment: inconclusive");
	expect_text(output, "assessment: succeeded_despite_denial");
	expect_text(output, "return_name: EPERM");
	expect_text(output, "return_name: ENOENT");
	expect_text(output, "not_granted_checks: 1");
	expect_text(output, "successful_capset_calls: 1");
	expect_text(output, "capset_only_capabilities:");
	expect_text(output, "name: sys_resource");
	expect_text(output, "denied_syscalls:");
	expect_text(output, "return_name: ERESTARTSYS\n"
		    "        errno: null");
	expect_text(output, "count: 20");
	free(output);
}

int main(void)
{
	if (classify_syscall_outcome(0) != SYSCALL_OUTCOME_SUCCESS ||
	    classify_syscall_outcome(-EPERM) != SYSCALL_OUTCOME_PERMISSION ||
	    classify_syscall_outcome(-EACCES) != SYSCALL_OUTCOME_PERMISSION ||
	    classify_syscall_outcome(-EINTR) != SYSCALL_OUTCOME_INTERRUPTED ||
	    classify_syscall_outcome(-EBADF) != SYSCALL_OUTCOME_OTHER ||
	    classify_syscall_outcome(-TEST_ERESTARTSYS) !=
					SYSCALL_OUTCOME_INTERRUPTED ||
	    syscall_result_errno(-EPERM) != EPERM ||
	    syscall_result_errno(-TEST_ERESTARTSYS) != 0 ||
	    !syscall_result_name(-ENOENT) ||
	    strcmp(syscall_result_name(-ENOENT), "ENOENT") != 0 ||
	    !syscall_result_name(-TEST_ERESTARTSYS) ||
	    strcmp(syscall_result_name(-TEST_ERESTARTSYS),
		   "ERESTARTSYS") != 0)
		fail("Raw syscall outcomes were misclassified");

	setup_events();
	if (state.app.checks[CAP_CHOWN].outcome_count != 0 ||
	    state.app.checks[CAP_NET_BIND_SERVICE].outcome_count != 1)
		fail("Syscall outcome was correlated to the wrong capability");
	if (state.app.capset.successful_calls != 1 ||
	    !cap_is_capset_only(CAP_SYS_RESOURCE) ||
	    cap_is_capset_only(CAP_NET_BIND_SERVICE) ||
	    cap_requested_by_capset(CAP_SYS_CHROOT))
		fail("capset payloads were not filtered or classified correctly");
	test_human_output();
	test_structured_output();

	puts("cap-audit syscall outcome tests passed");
	return 0;
}
