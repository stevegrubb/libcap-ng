// SPDX-License-Identifier: GPL-2.1-or-later
/*
 * cap-audit - Trace a target process to discover required capabilities.
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <libaudit.h>
#include <linux/capability.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include "cap-ng.h"
#include "cap_audit.skel.h"

typedef enum { UNSUPPORTED, ELF, PYTHON } type_t;
#define ELFMAG "\177ELF"

struct cap_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	int capability;
	int result;
	int syscall_nr;
	char comm[16];
	__u64 stack_id;
	__u32 targ_ns_inum;
};

struct cap_check {
	int capability;
	unsigned long count;
	unsigned long granted;
	unsigned long denied;
	int needed;
	char *reason;
	char **syscall_contexts;
	size_t num_contexts;
};

struct app_caps {
	pid_t pid;
	char *exe;
	type_t prog_type;
	struct cap_check checks[CAP_LAST_CAP + 1];
	int yama_ptrace_scope;
	int perf_event_paranoid;
	int unprivileged_bpf_disabled;
	int bpf_jit_enable;
	int bpf_jit_harden;
	int bpf_jit_kallsyms;
	char kernel_version[64];
};

struct audit_state {
	struct cap_audit_bpf *skel;
	struct ring_buffer *rb;
	struct app_caps app;
	int verbose;
	int json_output;
	int yaml_output;
	char **target_argv;
	volatile sig_atomic_t stop;
};

static struct audit_state state;
static int audit_machine = -1;

static void sig_handler(int sig)
{
	(void)sig;

	state.stop = 1;
}

/* Raise memlock rlimit for BPF loading */
static int set_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new) < 0) {
		fprintf(stderr, "Error: Failed to raise memlock rlimit: %s\n",
			errno == EPERM ?
			"insufficient privileges" : strerror(errno));
		return -1;
	}

	return 0;
}

int init_capng(void)
{
	capng_clear(CAPNG_SELECT_BOTH);

	if (capng_get_caps_process() != 0) {
		fprintf(stderr, "Error: Failed to get process capabilities\n");
		return -1;
	}

	return 0;
}

int check_audit_caps(void)
{
	if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_BPF) &&
	    !capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_ADMIN)) {
		fprintf(
			stderr,
			"Error: Need CAP_BPF or CAP_SYS_ADMIN to run auditor\n");
		return -1;
	}

	if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_PERFMON) &&
	    !capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_ADMIN)) {
		fprintf(stderr, "Error: Need CAP_PERFMON or CAP_SYS_ADMIN for "
			"perf events\n");
		return -1;
	}

	if (!capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_PTRACE))
		fprintf(stderr, "Warning: CAP_SYS_PTRACE not available, stack "
			"traces may be limited\n");

	return 0;
}

int set_target_pid(pid_t pid)
{
	int map_fd;
	__u8 val = 1;

	map_fd = bpf_map__fd(state.skel->maps.target_pids);
	if (map_fd < 0) {
		fprintf(stderr, "Error: Failed to get target_pids map fd\n");
		return -1;
	}

	if (bpf_map_update_elem(map_fd, &pid, &val, BPF_ANY) != 0) {
		fprintf(stderr, "Error: Failed to register target PID %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	if (state.verbose)
		printf("[*] Registered PID %d for tracing\n", pid);

	return 0;
}

void read_system_state(struct app_caps *app)
{
	FILE *f;

	f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
	if (f) {
		if (fscanf(f, "%d", &app->yama_ptrace_scope) != 1)
			app->yama_ptrace_scope = -1;
		fclose(f);
	} else {
		app->yama_ptrace_scope = -1;
	}

	f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
	if (f) {
		if (fscanf(f, "%d", &app->perf_event_paranoid) != 1)
			app->perf_event_paranoid = -1;
		fclose(f);
	} else {
		app->perf_event_paranoid = -1;
	}

	f = fopen("/proc/sys/kernel/unprivileged_bpf_disabled", "r");
	if (f) {
		if (fscanf(f, "%d", &app->unprivileged_bpf_disabled) != 1)
			app->unprivileged_bpf_disabled = -1;
		fclose(f);
	} else {
		app->unprivileged_bpf_disabled = -1;
	}

	f = fopen("/proc/sys/net/core/bpf_jit_enable", "r");
	if (f) {
		if (fscanf(f, "%d", &app->bpf_jit_enable) != 1)
			app->bpf_jit_enable = -1;
		fclose(f);
	} else {
		app->bpf_jit_enable = -1;
	}

	f = fopen("/proc/sys/net/core/bpf_jit_harden", "r");
	if (f) {
		if (fscanf(f, "%d", &app->bpf_jit_harden) != 1)
			app->bpf_jit_harden = -1;
		fclose(f);
	} else {
		app->bpf_jit_harden = -1;
	}

	f = fopen("/proc/sys/net/core/bpf_jit_kallsyms", "r");
	if (f) {
		if (fscanf(f, "%d", &app->bpf_jit_kallsyms) != 1)
			app->bpf_jit_kallsyms = -1;
		fclose(f);
	} else {
		app->bpf_jit_kallsyms = -1;
	}

	f = fopen("/proc/sys/kernel/osrelease", "r");
	if (f) {
		if (!fgets(app->kernel_version, sizeof(app->kernel_version), f))
			app->kernel_version[0] = 0;
		app->kernel_version[strcspn(app->kernel_version, "\n")] = 0;
		fclose(f);
	}
}

const char *syscall_name_from_nr(int nr)
{
	static int warned_machine;

	if (audit_machine < 0) {
		audit_machine = audit_detect_machine();
		if (audit_machine < 0 && !warned_machine) {
			fprintf(stderr, "Warning: unable to determine audit machine for syscall lookup\n");
			warned_machine = 1;
		}
	}

	if (audit_machine < 0)
		return NULL;

	return audit_syscall_to_name(nr, audit_machine);
}

static void update_reason(struct cap_check *check, int syscall_nr)
{
	const char *syscall_name;

	if (syscall_nr < 0) {
		if (asprintf(&check->reason,
			     "Used during capability check (syscall unknown)") < 0)
			check->reason = NULL;
		return;
	}

	syscall_name = syscall_name_from_nr(syscall_nr);
	if (check->reason)
		free(check->reason);

	if (asprintf(&check->reason, "Used by %s (syscall %d)",
		     syscall_name ? syscall_name : "unknown", syscall_nr) < 0)
		check->reason = NULL;
}

int handle_cap_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;
	const struct cap_event *e = data;

	if (state.verbose) {
		printf("[CAP] pid=%d cap=%d (%s) result=%s syscall=%d (%s) "
		       "comm=%s\n",
		       e->pid, e->capability,
		       capng_capability_to_name(e->capability),
		       e->result ? "GRANTED" : "DENIED", e->syscall_nr,
		       syscall_name_from_nr(e->syscall_nr) ?: "unknown",
		       e->comm);
	}

	if (e->capability >= 0 && e->capability <= CAP_LAST_CAP) {
		struct cap_check *check;

		check = &state.app.checks[e->capability];
		check->capability = e->capability;
		check->count++;

		if (e->result > 0)
			check->granted++;
		else if (e->result == 0)
			check->denied++;

		if (e->result > 0 && check->needed != 1) {
			check->needed = 1;
			update_reason(check, e->syscall_nr);
		}
	}

	return 0;
}

void analyze_capabilities(void)
{
	int has_required = 0;
	int has_conditional = 0;
	int has_denied = 0;
	int required_count = 0;
	int conditional_count = 0;
	int denied_count = 0;
	unsigned long total_checks = 0;
	int i;
	int first;

	printf("\n");
	printf("==============================================================="
	       "=======\n");
	printf("CAPABILITY ANALYSIS FOR: %s (PID %d)\n", state.app.exe,
	       state.app.pid);
	printf("==============================================================="
	       "=======\n\n");

	printf("SYSTEM CONTEXT:\n");
	printf("---------------------------------------------------------------"
	       "-------\n");
	printf("  Kernel version: %s\n", state.app.kernel_version);
	printf("  kernel.yama.ptrace_scope: %d\n", state.app.yama_ptrace_scope);
	printf("  kernel.perf_event_paranoid: %d\n",
	       state.app.perf_event_paranoid);
	printf("  kernel.unprivileged_bpf_disabled: %d\n",
	       state.app.unprivileged_bpf_disabled);
	printf("  net.core.bpf_jit_enable: %d\n", state.app.bpf_jit_enable);
	printf("  net.core.bpf_jit_harden: %d\n", state.app.bpf_jit_harden);
	printf("  net.core.bpf_jit_kallsyms: %d\n",
	       state.app.bpf_jit_kallsyms);
	printf("\n");

	printf("REQUIRED CAPABILITIES:\n");
	printf("---------------------------------------------------------------"
	       "-------\n");
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check;

		check = &state.app.checks[i];
		if (check->granted > 0) {
			has_required = 1;
			printf("  %s (#%d)\n", capng_capability_to_name(i), i);
			printf("    Checks: %lu granted, %lu denied\n",
			       check->granted, check->denied);
			if (check->reason)
				printf("    Reason: %s\n", check->reason);
			printf("\n");
		}
	}
	if (!has_required)
		printf("  None - Application does not require elevated "
		       "capabilities!\n\n");

	printf("CONDITIONAL CAPABILITIES:\n");
	printf("---------------------------------------------------------------"
	       "-------\n");

	if (state.app.yama_ptrace_scope > 0) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].count > 0 &&
			    state.app.checks[i].granted == 0 &&
			    i == CAP_SYS_PTRACE) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYS_PTRACE\n");
				printf("    Needed when "
				       "kernel.yama.ptrace_scope > 0\n");
				printf("    Current value: %d (capability "
				       "needed)\n",
				       state.app.yama_ptrace_scope);
				printf("\n");
			}
		}
	}

	if (state.app.perf_event_paranoid >= 2) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].count > 0 && i == CAP_PERFMON) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_PERFMON\n");
				printf("    Needed when "
				       "kernel.perf_event_paranoid >= 2\n");
				printf("    Current value: %d (capability "
				       "needed)\n",
				       state.app.perf_event_paranoid);
				printf("    Note: CAP_SYS_ADMIN can substitute "
				       "on kernels < 5.8\n");
				printf("\n");
			}
		}
	}

	if (state.app.unprivileged_bpf_disabled == 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].count > 0 && i == CAP_BPF) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_BPF\n");
				printf(
				       "    Needed when "
				       "kernel.unprivileged_bpf_disabled = 1\n");
				printf("    Current value: %d (capability "
				       "needed)\n",
				       state.app.unprivileged_bpf_disabled);
				printf("    Note: CAP_SYS_ADMIN can substitute "
				       "on kernels < 5.8\n");
				printf("\n");
			}
		}
	}

	if (!has_conditional)
		printf("  None\n\n");

	printf("ATTEMPTED BUT DENIED:\n");
	printf("---------------------------------------------------------------"
	       "-------\n");
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check;

		check = &state.app.checks[i];
		if (check->denied > 0 && check->granted == 0) {
			has_denied = 1;
			printf("  %s (#%d)\n", capng_capability_to_name(i), i);
			printf("    Attempts: %lu (all denied)\n",
			       check->denied);
			printf("    Impact: Application may have reduced "
			       "functionality\n");
			printf("\n");
		}
	}
	if (!has_denied)
		printf("  None\n\n");

	for (i = 0; i <= CAP_LAST_CAP; i++) {
		total_checks += state.app.checks[i].count;
		if (state.app.checks[i].granted > 0)
			required_count++;
		if (state.app.checks[i].denied > 0 &&
		    state.app.checks[i].granted == 0)
			denied_count++;
	}

	printf("SUMMARY:\n");
	printf("---------------------------------------------------------------"
	       "-------\n");
	printf("  Total capability checks: %lu\n", total_checks);
	printf("  Required capabilities: %d\n", required_count);
	printf("  Conditional capabilities: %d\n", conditional_count);
	printf("  Denied operations: %d\n", denied_count);
	printf("\n");

	if (required_count > 0) {
		printf("RECOMMENDATIONS:\n");
		printf("-------------------------------------------------------"
		       "---------------\n");

		printf("  For systemd service:\n");
		printf("    [Service]\n");
		printf("    User=<non-root-user>\n");
		printf("    Group=<non-root-group>\n");
		printf("    AmbientCapabilities=");
		first = 1;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].granted > 0) {
				if (!first)
					printf(" ");
				printf("%s", capng_capability_to_name(i));
				first = 0;
			}
		}
		printf("\n");
		printf("    CapabilityBoundingSet=");
		first = 1;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].granted > 0) {
				if (!first)
					printf(" ");
				printf("%s", capng_capability_to_name(i));
				first = 0;
			}
		}
		printf("\n\n");

		printf("  For file capabilities (via filecap):\n");
		printf("    filecap /path/to/binary");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].granted > 0)
				printf(" %s", capng_capability_to_name(i));
		}
		printf("\n\n");

		printf("  For Docker/Podman:\n");
		printf("    docker run --user $(id -u):$(id -g) \\\n");
		printf("      --cap-drop=ALL \\\n");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].granted > 0)
				printf("      --cap-add=%s \\\n",
				       capng_capability_to_name(i));
		}
		printf("      your-image:tag\n\n");

		printf("  For Kubernetes:\n");
		printf("    securityContext:\n");
		printf("      runAsUser: 1000\n");
		printf("      runAsGroup: 1000\n");
		printf("      capabilities:\n");
		printf("        drop:\n");
		printf("          - ALL\n");
		printf("        add:\n");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (state.app.checks[i].granted > 0)
				printf("          - %s\n",
				       capng_capability_to_name(i));
		}
		printf("\n");
	} else {
		printf("RECOMMENDATIONS:\n");
		printf("-------------------------------------------------------"
		       "---------------\n");
		printf("  This application does not require any elevated "
		       "capabilities!\n");
		printf("  Run as an unprivileged user with no special "
		       "capabilities.\n\n");
	}

	printf("==============================================================="
	       "=======\n");
}

void output_json(void)
{
	int i;
	int first_cap;
	int first_denied;

	printf("{\n");
	printf("  \"application\": {\n");
	printf("    \"pid\": %d,\n", state.app.pid);
	printf("    \"comm\": \"%s\"\n", state.app.exe);
	printf("  },\n");

	printf("  \"system_context\": {\n");
	printf("    \"kernel_version\": \"%s\",\n",
	       state.app.kernel_version);
	printf("    \"yama_ptrace_scope\": %d,\n", state.app.yama_ptrace_scope);
	printf("    \"perf_event_paranoid\": %d,\n",
	       state.app.perf_event_paranoid);
	printf("    \"unprivileged_bpf_disabled\": %d,\n",
	       state.app.unprivileged_bpf_disabled);
	printf("    \"bpf_jit_enable\": %d,\n", state.app.bpf_jit_enable);
	printf("    \"bpf_jit_harden\": %d,\n", state.app.bpf_jit_harden);
	printf("    \"bpf_jit_kallsyms\": %d\n",
	       state.app.bpf_jit_kallsyms);
	printf("  },\n");

	printf("  \"required_capabilities\": [\n");
	first_cap = 1;
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check = &state.app.checks[i];

		if (check->granted > 0) {
			if (!first_cap)
				printf(",\n");
			printf("    {\n");
			printf("      \"number\": %d,\n", i);
			printf("      \"name\": \"%s\",\n",
			       capng_capability_to_name(i));
			printf("      \"checks\": {\n");
			printf("        \"total\": %lu,\n", check->count);
			printf("        \"granted\": %lu,\n", check->granted);
			printf("        \"denied\": %lu\n", check->denied);
			printf("      }");
			if (check->reason)
				printf(",\n      \"reason\": \"%s\"\n",
				       check->reason);
			else
				printf("\n");
			printf("    }");
			first_cap = 0;
		}
	}
	printf("\n  ],\n");

	printf("  \"denied_capabilities\": [\n");
	first_denied = 1;
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check = &state.app.checks[i];

		if (check->denied > 0 && check->granted == 0) {
			if (!first_denied)
				printf(",\n");
			printf("    {\n");
			printf("      \"number\": %d,\n", i);
			printf("      \"name\": \"%s\",\n",
			       capng_capability_to_name(i));
			printf("      \"attempts\": %lu\n", check->denied);
			printf("    }");
			first_denied = 0;
		}
	}
	printf("\n  ]\n");
	printf("}\n");
}

void output_yaml(void) {
	int i;

	printf("application:\n");
	printf("  pid: %d\n", state.app.pid);
	printf("  comm: \"%s\"\n", state.app.exe);

	printf("system_context:\n");
	printf("  kernel_version: \"%s\"\n", state.app.kernel_version);
	printf("  yama_ptrace_scope: %d\n", state.app.yama_ptrace_scope);
	printf("  perf_event_paranoid: %d\n",
	       state.app.perf_event_paranoid);
	printf("  unprivileged_bpf_disabled: %d\n",
	       state.app.unprivileged_bpf_disabled);
	printf("  bpf_jit_enable: %d\n", state.app.bpf_jit_enable);
	printf("  bpf_jit_harden: %d\n", state.app.bpf_jit_harden);
	printf("  bpf_jit_kallsyms: %d\n", state.app.bpf_jit_kallsyms);

	printf("required_capabilities:\n");
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check = &state.app.checks[i];

		if (check->granted > 0) {
			printf("  - number: %d\n", i);
			printf("    name: %s\n",
			       capng_capability_to_name(i));
			printf("    checks:\n");
			printf("      total: %lu\n", check->count);
			printf("      granted: %lu\n", check->granted);
			printf("      denied: %lu\n", check->denied);
			if (check->reason)
				printf("    reason: \"%s\"\n",
				       check->reason);
		}
	}

	printf("denied_capabilities:\n");
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check = &state.app.checks[i];

		if (check->denied > 0 && check->granted == 0) {
			printf("  - number: %d\n", i);
			printf("    name: %s\n",
			       capng_capability_to_name(i));
			printf("    attempts: %lu\n", check->denied);
		}
	}
}

type_t classify_app(const char *exe)
{
	int fd;
	char buf[257];

	fd = open(exe, O_RDONLY|O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s - %s\n", exe, strerror(errno));
		exit(1);
	}

	// classify the app
	ssize_t rc = read(fd, buf, 256);
	close(fd);
	if (rc > 0) {
		// terminate buffer
		buf[rc] = 0;
		// limit search to first line
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = 0;
		// check for shebang
		if (buf[0] == '#' && buf[1] == '!') {
			// see if python is anywhere on first line
			if (strstr(buf, "python"))
				return PYTHON;
			// next check if elf binary
		} else if (strncmp(buf, ELFMAG, 4))
			return ELF;
	}

	// If neither, then libcap-ng doesn't suport it
	return UNSUPPORTED;
}

int main(int argc, char **argv)
{
	int err;
	int arg_idx;
	pid_t child;
	pid_t ret_pid;
	int wstatus;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [options] -- command [args...]\n",
			argv[0]);
		fprintf(stderr, "Options:\n");
		fprintf(stderr, "  -v, --verbose    Verbose output\n");
		fprintf(stderr, "  -j, --json       JSON output\n");
		fprintf(stderr, "  -y, --yaml       YAML output\n");
		return 1;
	}

	arg_idx = 1;
	while (arg_idx < argc && argv[arg_idx][0] == '-') {
		if (!strcmp(argv[arg_idx], "-v") ||
		    !strcmp(argv[arg_idx], "--verbose"))
			state.verbose = 1;
		else if (!strcmp(argv[arg_idx], "-j") ||
			 !strcmp(argv[arg_idx], "--json"))
			state.json_output = 1;
		else if (!strcmp(argv[arg_idx], "-y") ||
			 !strcmp(argv[arg_idx], "--yaml"))
			state.yaml_output = 1;
		else if (!strcmp(argv[arg_idx], "--")) {
			arg_idx++;
			break;
		}
		arg_idx++;
	}

	if (arg_idx >= argc) {
		fprintf(stderr, "Error: No command specified\n");
		return 1;
	}

	state.target_argv = &argv[arg_idx];
	if (init_capng() != 0)
		return 1;

	if (check_audit_caps() != 0)
		return 1;

	if (set_memlock_rlimit() != 0)
		return 1;

	state.app.exe = strdup(state.target_argv[0]);
	state.app.prog_type = classify_app(state.app.exe);

	state.skel = cap_audit_bpf__open_and_load();
	if (!state.skel) {
		fprintf(stderr, "Error: Failed to load BPF program: %s\n",
			strerror(errno));
		return 1;
	}

	err = cap_audit_bpf__attach(state.skel);
	if (err) {
		fprintf(stderr, "Error: Failed to attach BPF programs: %s\n",
			strerror(-err));
		cap_audit_bpf__destroy(state.skel);
		return 1;
	}

	state.rb = ring_buffer__new(bpf_map__fd(state.skel->maps.cap_events),
				    handle_cap_event, NULL, NULL);
	if (!state.rb) {
		fprintf(stderr, "Error: Failed to create ring buffer: %s\n",
			strerror(errno));
		cap_audit_bpf__destroy(state.skel);
		return 1;
	}

	printf("[*] Capability auditor started\n");

	child = fork();
	if (child == 0) {
		usleep(100000);
		execvp(state.target_argv[0], state.target_argv);
		perror("execvp");
		exit(1);
	} else if (child < 0) {
		fprintf(stderr, "Error: fork failed: %s\n", strerror(errno));
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		return 1;
	}

	state.app.pid = child;

	if (set_target_pid(child) != 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		return 1;
	}

	read_system_state(&state.app);

	printf("[*] Tracing application: %s (PID %d)\n", state.app.exe, child);
	printf("[*] Press Ctrl-C to stop\n\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!state.stop) {
		err = ring_buffer__poll(state.rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %s\n",
				strerror(-err));
			break;
		}

		ret_pid = waitpid(child, &wstatus, WNOHANG);
		if (ret_pid == child) {
			if (WIFEXITED(wstatus))
				printf(
				       "\n[*] Application exited with status %d\n",
				       WEXITSTATUS(wstatus));
			else if (WIFSIGNALED(wstatus))
				printf("\n[*] Application terminated by signal "
				       "%d\n",
				       WTERMSIG(wstatus));
			break;
		}
	}

	printf("[*] Analyzing results...\n");

	usleep(100000);
	ring_buffer__poll(state.rb, 0);

	if (state.json_output)
		output_json();
	else if (state.yaml_output)
		output_yaml();
	else
		analyze_capabilities();

	ring_buffer__free(state.rb);
	cap_audit_bpf__destroy(state.skel);
	free(state.app.exe);

	for (int i = 0; i <= CAP_LAST_CAP; i++) {
		if (state.app.checks[i].reason)
			free(state.app.checks[i].reason);
	}

	return 0;
}

