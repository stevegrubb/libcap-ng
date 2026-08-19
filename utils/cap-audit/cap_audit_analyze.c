// SPDX-License-Identifier: GPL-2.0-or-later
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
 *   Portions of this code were made with codex 5.2
 */

/* Human-readable analysis output: capability summaries, deployment
 * recommendations, and wrapped terminal formatting helpers.
 */

#include "cap_audit.h"

#include <ctype.h>
#include <grp.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int include_cap_in_recommendations(int cap)
{
	if (cap == CAP_SETPCAP && state.app.file_caps &&
	    !state.app.file_setpcap)
		return 0;

	return 1;
}

static void cap_name_upper_buf(int cap, char *buf, size_t buf_len)
{
	const char *name = cap_name_safe(cap);
	size_t i;

	if (buf_len == 0)
		return;

	for (i = 0; name[i] && i + 1 < buf_len; i++)
		buf[i] = toupper((unsigned char)name[i]);
	buf[i] = '\0';
}

static int get_output_width(void)
{
	struct winsize ws;
	const char *columns;
	long env_width;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
		return ws.ws_col;

	columns = getenv("COLUMNS");
	if (columns) {
		env_width = strtol(columns, NULL, 10);
		if (env_width >= 40 && env_width <= 400)
			return (int)env_width;
	}

	return 80;
}

static void print_rule(char ch)
{
	int i;
	int width = get_output_width();

	if (width < 40)
		width = 40;

	for (i = 0; i < width; i++)
		putchar(ch);
	putchar('\n');
}

static void print_wrapped_text(const char *indent, const char *text)
{
	size_t indent_len;
	char *cont_indent;
	int width;
	int content_width;
	const char *p;
	int line_len = 0;
	int first_line = 1;

	if (!text) {
		printf("%s\n", indent);
		return;
	}

	indent_len = strlen(indent);
	cont_indent = malloc(indent_len + 1);
	if (!cont_indent) {
		printf("%s%s\n", indent, text);
		return;
	}
	memset(cont_indent, ' ', indent_len);
	cont_indent[indent_len] = '\0';

	width = get_output_width();
	if (width < 40)
		width = 40;
	content_width = width - (int)indent_len;
	if (content_width < 16)
		content_width = 16;

	printf("%s", indent);
	p = text;
	while (*p) {
		size_t word_len;
		int need_space = line_len > 0;

		while (*p == ' ')
			p++;

		if (*p == '\n') {
			putchar('\n');
			printf("%s", first_line ? cont_indent : cont_indent);
			line_len = 0;
			first_line = 0;
			p++;
			continue;
		}
		if (*p == '\0')
			break;

		word_len = strcspn(p, " \n");
		if (need_space &&
		    line_len + 1 + (int)word_len > content_width) {
			putchar('\n');
			printf("%s", cont_indent);
			line_len = 0;
			need_space = 0;
			first_line = 0;
		}
		if (need_space) {
			putchar(' ');
			line_len++;
		}
		fwrite(p, 1, word_len, stdout);
		line_len += word_len;
		p += word_len;
	}
	putchar('\n');
	free(cont_indent);
}

static void print_wrappedf(const char *indent, const char *fmt, ...)
{
	va_list ap;
	char *buf;

	va_start(ap, fmt);
	if (vasprintf(&buf, fmt, ap) < 0)
		buf = NULL;
	va_end(ap);

	if (buf) {
		print_wrapped_text(indent, buf);
		free(buf);
	} else {
		print_wrapped_text(indent, "(formatting error)");
	}
}

static int cap_in_programmatic_set(int cap)
{
	if (!include_cap_in_recommendations(cap))
		return 0;

	if (state.capset_observed)
		return state.app.checks[cap].op_granted > 0;

	return state.app.checks[cap].granted > 0;
}

static bool svc_is_root_service(const service_config_t *cfg)
{
	return !cfg->user_is_set || cfg->user_uid == 0;
}

static gid_t svc_effective_gid(const service_config_t *cfg)
{
	if (cfg->group_is_set)
		return cfg->group_gid;
	if (cfg->user_is_set)
		return cfg->user_primary_gid;
	return 0;
}

static const char *svc_group_name(gid_t gid, char *buf, size_t buf_len)
{
	struct group *grp;

	grp = getgrgid(gid);
	if (grp)
		return grp->gr_name;

	snprintf(buf, buf_len, "%u", (unsigned int)gid);
	return buf;
}

static const char *svc_user_name(const service_config_t *cfg)
{
	if (cfg->user_is_set && cfg->user_raw)
		return cfg->user_raw;

	return "root";
}

static void svc_print_cap_list(const bool caps[CAP_LAST_CAP + 1])
{
	int cap;
	int first = 1;

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		if (!caps[cap])
			continue;
		if (!first)
			printf(" ");
		printf("%s", cap_name_safe(cap));
		first = 0;
	}
	if (first)
		printf("(none)");
}

static void svc_print_cap_set(const cap_set_t *set)
{
	if (!set->seen) {
		printf("not configured (all capabilities inherited)");
		return;
	}

	svc_print_cap_list(set->caps);
}

static void svc_build_recommended_caps(bool caps[CAP_LAST_CAP + 1])
{
	int cap;

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		struct cap_check *check = &state.app.checks[cap];

		caps[cap] = false;
		if (!include_cap_in_recommendations(cap))
			continue;
		/*
		 * A denied check may be advisory or precede a fallback, so it
		 * does not prove that the capability is required.
		 */
		if (cap_required_union(check))
			caps[cap] = true;
	}
}

static void svc_print_reason(const struct cap_check *check)
{
	const char *reason = cap_union_reason(check);

	if (reason)
		printf(" (%s)", reason);
}

static void svc_print_needed_caps(void)
{
	int cap;
	int found = 0;

	printf("    Needed capabilities:");
	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		struct cap_check *check = &state.app.checks[cap];

		if (!cap_required_union(check) ||
		    !include_cap_in_recommendations(cap))
			continue;
		if (!found)
			printf("\n");
		printf("      %s", cap_name_safe(cap));
		svc_print_reason(check);
		printf("\n");
		found = 1;
	}
	if (!found)
		printf(" none\n");
}

static void svc_print_phase_caps(const char *label, int operational)
{
	int cap;
	int first = 1;

	printf("    %s", label);
	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		struct cap_check *check = &state.app.checks[cap];
		unsigned long granted;

		granted = operational ? check->op_granted : check->granted;
		if (granted == 0 || !include_cap_in_recommendations(cap))
			continue;
		if (!first)
			printf(" ");
		printf("%s", cap_name_safe(cap));
		first = 0;
	}
	if (first)
		printf("none");
	printf("\n");
}

static void svc_print_denied_syscalls(const struct cap_check *check)
{
	size_t j;

	if (check->denied_syscall_count == 0) {
		printf("unknown");
		return;
	}

	for (j = 0; j < check->denied_syscall_count; j++) {
		const char *syscall_name;

		if (j > 0)
			printf(", ");
		syscall_name = syscall_name_from_nr(check->denied_syscalls[j]);
		if (syscall_name)
			printf("%s", syscall_name);
		else
			printf("unknown(#%d)", check->denied_syscalls[j]);
	}
}

static void svc_print_denied_caps(const service_config_t *cfg)
{
	int cap;
	int found = 0;

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		struct cap_check *check = &state.app.checks[cap];
		unsigned long denied = cap_total_denied(check);
		int by_bounding;

		if (denied == 0 || !include_cap_in_recommendations(cap))
			continue;

		by_bounding = cfg->bounding.seen && !cfg->bounding.caps[cap];
		printf("    %s: %s - %lu attempts (",
		       by_bounding ? "Denied by bounding set" :
		       "Denied for other reasons",
		       cap_name_safe(cap), denied);
		svc_print_denied_syscalls(check);
		printf(")\n");
		if (!cap_required_union(check))
			print_wrapped_text("      ",
					   "Denied checks alone do not prove that a "
					   "capability is required. Treat denied-only "
					   "capabilities as candidates for manual "
					   "investigation and add one only if its "
					   "associated functionality is confirmed "
					   "to fail.");
		else if (by_bounding)
			print_wrapped_text("      ",
					   "Consider adding to CapabilityBoundingSet if this functionality is needed.");
		found = 1;
	}

	if (!found)
		printf("    Denied capabilities: none\n");
}

static void svc_print_unused_bounding(const service_config_t *cfg)
{
	int cap;
	int found = 0;

	if (!cfg->bounding.seen)
		return;

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		struct cap_check *check = &state.app.checks[cap];

		if (!cfg->bounding.caps[cap] ||
		    cap_total_checks(check) > 0)
			continue;
		printf("    Configured but not observed: %s\n",
		       cap_name_safe(cap));
		print_wrapped_text("      ",
				   "Consider removing from CapabilityBoundingSet to minimize attack surface.");
		found = 1;
	}

	if (!found)
		printf("    Configured but not observed: none\n");
}

static void print_service_recommendations(void)
{
	const service_config_t *cfg = state.service_cfg;
	bool recommended[CAP_LAST_CAP + 1];
	char group_buf[32];
	gid_t gid = svc_effective_gid(cfg);
	const char *group = svc_group_name(gid, group_buf, sizeof(group_buf));
	int is_root = svc_is_root_service(cfg);

	svc_build_recommended_caps(recommended);

	printf("SYSTEMD SERVICE RECOMMENDATIONS:\n");
	print_rule('-');
	printf("  Unit file: %s\n", state.service_file);
	printf("  ExecStart: %s\n", cfg->exec_start ?
	       cfg->exec_start : "(not configured)");
	printf("  User: %s (uid=%u)\n", svc_user_name(cfg),
	       cfg->user_is_set ? (unsigned int)cfg->user_uid : 0);
	printf("  Group: %s (gid=%u)\n", group, (unsigned int)gid);
	printf("  NoNewPrivileges: %s\n",
	       cfg->no_new_privs ? "yes" : "no");
	printf("\n");
	printf("  Current CapabilityBoundingSet: ");
	svc_print_cap_set(&cfg->bounding);
	printf("\n\n");

	printf("  Analysis:\n");
	svc_print_needed_caps();
	if (state.capset_observed) {
		print_wrapped_text("    ",
				   "capset was observed. CapabilityBoundingSet "
				   "should include the union of initialization "
				   "and operational capabilities.");
		svc_print_phase_caps("Initialization capabilities: ", 0);
		svc_print_phase_caps("Operational capabilities: ", 1);
	}
	if (is_root)
		print_wrapped_text("    ",
				   "AmbientCapabilities omitted because ambient "
				   "capabilities are not meaningful for root "
				   "services.");
	svc_print_denied_caps(cfg);
	svc_print_unused_bounding(cfg);
	printf("\n");

	printf("  Recommended [Service] configuration:\n");
	printf("    [Service]\n");
	printf("    User=%s\n", svc_user_name(cfg));
	printf("    Group=%s\n", group);
	if (is_root)
		printf("    # AmbientCapabilities omitted for root service\n");
	else {
		printf("    AmbientCapabilities=");
		svc_print_cap_list(recommended);
		printf("\n");
	}
	printf("    CapabilityBoundingSet=");
	svc_print_cap_list(recommended);
	printf("\n");
	printf("    NoNewPrivileges=yes\n\n");
}

static void print_updatev_wrapped(const char *prefix, const char *cap_prefix,
				  const char *suffix)
{
	int width = get_output_width();
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);
	int cur_len = prefix_len;
	int cont_indent = 8;
	int i;

	if (width < 40)
		width = 40;

	for (i = 0; prefix[i] == ' '; i++)
		;
	if (i > 0)
		cont_indent = i + 4;

	printf("%s", prefix);
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		char cap_name[64];
		char item[96];
		size_t item_len;

		if (!cap_in_programmatic_set(i))
			continue;

		cap_name_upper_buf(i, cap_name, sizeof(cap_name));
		snprintf(item, sizeof(item), "%s%s", cap_prefix, cap_name);
		item_len = strlen(item);

		if (cur_len > (int)prefix_len &&
		    cur_len + 2 + (int)item_len + (int)suffix_len > width) {
			printf(",\n%*s%s", cont_indent, "", item);
			cur_len = cont_indent + item_len;
		} else {
			printf(", %s", item);
			cur_len += 2 + item_len;
		}
	}

	if (cur_len + 2 + (int)suffix_len > width && cur_len > cont_indent) {
		printf(",\n%*s%s", cont_indent, "", suffix);
	} else {
		printf(", %s", suffix);
	}
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
	print_rule('=');
	print_wrappedf("", "CAPABILITY ANALYSIS FOR: %s (PID %d)",
		       state.app.exe, state.app.pid);
	print_rule('=');
	printf("\n");

	printf("SYSTEM CONTEXT:\n");
	print_rule('-');
	printf("  Kernel version: %s\n", state.app.kernel_version);
	printf("  kernel.yama.ptrace_scope: %d\n", state.app.yama_ptrace_scope);
	printf("  kernel.kptr_restrict: %d\n", state.app.kptr_restrict);
	printf("  kernel.dmesg_restrict: %d\n", state.app.dmesg_restrict);
	printf("  kernel.modules_disabled: %d\n", state.app.modules_disabled);
	printf("  kernel.perf_event_paranoid: %d\n",
	       state.app.perf_event_paranoid);
	printf("  kernel.unprivileged_bpf_disabled: %d\n",
	       state.app.unprivileged_bpf_disabled);
	printf("  net.core.bpf_jit_enable: %d\n", state.app.bpf_jit_enable);
	printf("  net.core.bpf_jit_harden: %d\n", state.app.bpf_jit_harden);
	printf("  net.core.bpf_jit_kallsyms: %d\n",
	       state.app.bpf_jit_kallsyms);
	printf("  vm.mmap_min_addr: %d\n", state.app.mmap_min_addr);
	printf("  fs.protected_hardlinks: %d\n", state.app.protected_hardlinks);
	printf("  fs.protected_symlinks: %d\n", state.app.protected_symlinks);
	printf("  fs.suid_dumpable: %d\n", state.app.suid_dumpable);
	printf("\n");

	printf("REQUIRED CAPABILITIES:\n");
	print_rule('-');
	if (!state.capset_observed) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			struct cap_check *check;

			check = &state.app.checks[i];
			if (check->granted > 0) {
				has_required = 1;
				printf("  %s (#%d)\n", cap_name_safe(i), i);
				printf("    Checks: %lu granted, %lu denied\n",
				       check->granted, check->denied);
				if (check->reason)
					print_wrappedf("    Reason: ",
						       "%s", check->reason);
				if (!include_cap_in_recommendations(i))
					print_wrapped_text("    Note: ",
							   "Internal to capability setup; excluded from recommendations.");
				printf("\n");
			}
		}
		if (!has_required)
			print_wrapped_text("  ",
					   "None - Application does not require elevated capabilities!\n");
	} else {
		print_wrapped_text("",
				   "INITIALIZATION CAPABILITIES (before capability drop):");
		print_rule('-');
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			struct cap_check *check = &state.app.checks[i];

			if (check->granted > 0) {
				has_required = 1;
				printf("  %s (#%d)\n", cap_name_safe(i), i);
				printf("    Checks: %lu granted, %lu denied\n",
				       check->granted, check->denied);
				if (check->reason)
					print_wrappedf("    Reason: ",
						       "%s", check->reason);
				if (!include_cap_in_recommendations(i))
					print_wrapped_text("    Note: ",
							   "Internal to capability setup; excluded from recommendations.");
				printf("\n");
			}
		}
		if (!has_required)
			printf("  None\n\n");

		print_wrapped_text("",
				   "OPERATIONAL CAPABILITIES (after capability drop):");
		print_rule('-');
		has_required = 0;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			struct cap_check *check = &state.app.checks[i];

			if (check->op_granted > 0) {
				has_required = 1;
				printf("  %s (#%d)\n", cap_name_safe(i), i);
				printf("    Checks: %lu granted, %lu denied\n",
				       check->op_granted, check->op_denied);
				if (check->op_reason)
					print_wrappedf("    Reason: ",
						       "%s", check->op_reason);
				if (!include_cap_in_recommendations(i))
					print_wrapped_text("    Note: ",
							   "Internal to capability setup; excluded from recommendations.");
				printf("\n");
			}
		}
		if (!has_required)
			printf("  None\n\n");
	}

	printf("CONDITIONAL CAPABILITIES:\n");
	print_rule('-');

	if (state.app.yama_ptrace_scope > 0) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    state.app.checks[i].granted == 0 &&
			    i == CAP_SYS_PTRACE) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYS_PTRACE\n");
				print_wrapped_text("    ",
						   "Needed when kernel.yama.ptrace_scope > 0");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.yama_ptrace_scope);
				printf("\n");
			}
		}
	}

	if (state.app.perf_event_paranoid >= 2) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_PERFMON) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_PERFMON\n");
				print_wrapped_text("    ",
						   "Needed when kernel.perf_event_paranoid >= 2");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.perf_event_paranoid);
				print_wrapped_text("    Note: ",
						   "CAP_SYS_ADMIN can substitute on kernels < 5.8");
				printf("\n");
			}
		}
	}

	if (state.app.unprivileged_bpf_disabled == 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_BPF) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_BPF\n");
				print_wrapped_text("    ",
						   "Needed when kernel.unprivileged_bpf_disabled = 1");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.unprivileged_bpf_disabled);
				print_wrapped_text("    Note: ",
						   "CAP_SYS_ADMIN can substitute on kernels < 5.8");
				printf("\n");
			}
		}
	}

	if (state.app.kptr_restrict >= 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_SYSLOG) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYSLOG\n");
				print_wrapped_text("    ",
						   "Needed when kernel.kptr_restrict >= 1");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.kptr_restrict);
				printf("\n");
			}
		}
	}

	if (state.app.dmesg_restrict >= 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_SYSLOG) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYSLOG\n");
				print_wrapped_text("    ",
						   "Needed when kernel.dmesg_restrict >= 1");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.dmesg_restrict);
				printf("\n");
			}
		}
	}

	if (state.app.modules_disabled == 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_SYS_MODULE) {
				has_conditional = 1;
				conditional_count++;
				printf("  NOTE: kernel.modules_disabled = 1\n");
				print_wrapped_text("    ",
						   "CAP_SYS_MODULE is ineffective!");
				print_wrapped_text("    ",
						   "Module loading is permanently disabled.");
				printf("\n");
			}
		}
	}

	if (state.app.mmap_min_addr > 0) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_SYS_RAWIO) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYS_RAWIO\n");
				print_wrapped_text("    ",
						   "Needed when vm.mmap_min_addr > 0 to map low addresses");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.mmap_min_addr);
				printf("\n");
			}
		}
	}

	if (state.app.protected_hardlinks == 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_FOWNER) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_FOWNER\n");
				print_wrapped_text("    ",
						   "Needed when fs.protected_hardlinks = 1 to link files not owned by the caller");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.protected_hardlinks);
				printf("\n");
			}
		}
	}

	if (state.app.protected_symlinks == 1) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_DAC_OVERRIDE) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_DAC_OVERRIDE\n");
				print_wrapped_text("    ",
						   "Needed when fs.protected_symlinks = 1 for symlinks in world-writable directories");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.protected_symlinks);
				printf("\n");
			}
		}
	}

	if (state.app.suid_dumpable == 2) {
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_total_checks(&state.app.checks[i]) > 0 &&
			    i == CAP_SYS_PTRACE) {
				has_conditional = 1;
				conditional_count++;
				printf("  CAP_SYS_PTRACE\n");
				print_wrapped_text("    ",
						   "Needed when fs.suid_dumpable = 2 for core dumps and ptrace of setuid programs");
				print_wrappedf("    ",
					       "Current value: %d (capability needed)",
					       state.app.suid_dumpable);
				printf("\n");
			}
		}
	}

	if (!has_conditional)
		printf("  None\n\n");

	printf("ATTEMPTED BUT DENIED:\n");
	print_rule('-');
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		struct cap_check *check;

		check = &state.app.checks[i];
		if (cap_total_denied(check) > 0 && cap_total_granted(check) == 0) {
			size_t j;

			has_denied = 1;
			printf("  %s (#%d)\n", cap_name_safe(i), i);
			printf("    Attempts: %lu (all denied)\n",
			       cap_total_denied(check));
			printf("    Syscalls: ");
			if (check->denied_syscall_count == 0)
				printf("unknown\n");
			for (j = 0; j < check->denied_syscall_count; j++) {
				const char *syscall_name;
				int syscall_nr;

				syscall_nr = check->denied_syscalls[j];
				syscall_name = syscall_name_from_nr(syscall_nr);
				if (j > 0)
					printf(", ");
				if (syscall_name)
					printf("%s", syscall_name);
				else
					printf("unknown(#%d)", syscall_nr);
			}
			if (check->denied_syscall_count > 0)
				printf("\n");
			print_wrapped_text("    Impact: ",
					   "Application may have reduced functionality");
			printf("\n");
		}
	}
	if (!has_denied)
		printf("  None\n\n");

	for (i = 0; i <= CAP_LAST_CAP; i++) {
		total_checks += cap_total_checks(&state.app.checks[i]);
		if (cap_required_union(&state.app.checks[i]))
			required_count++;
		if (cap_total_denied(&state.app.checks[i]) > 0 &&
		    cap_total_granted(&state.app.checks[i]) == 0)
			denied_count++;
	}

	printf("SUMMARY:\n");
	print_rule('-');
	printf("  Total capability checks: %lu\n", total_checks);
	printf("  Required capabilities: %d\n", required_count);
	printf("  Conditional capabilities: %d\n", conditional_count);
	printf("  Denied operations: %d\n", denied_count);
	printf("\n");

	if (state.foreign_target_ns_observed) {
		printf("RECOMMENDATIONS:\n");
		print_rule('-');
		print_wrapped_text("  Warning: ",
				   "Capability checks targeted a different user "
				   "namespace. Automatic capability recommendations "
				   "are suppressed because their safe scope cannot "
				   "be determined.");
		printf("\n");
	} else if (state.service_cfg) {
		print_service_recommendations();
	} else if (required_count > 0) {
		printf("RECOMMENDATIONS:\n");
		print_rule('-');
		if (state.app.prog_type != UNSUPPORTED) {
			printf("  Programmatic solution (%s):\n",
			       state.app.prog_type == ELF ?
			       "C with libcap-ng" :
			       "Python with python3-libcap-ng");
			if (state.capset_observed)
				print_wrapped_text("    Note: ",
						   "The application drops capabilities after initialization. The programmatic snippet reflects the operational set only.");

			if (state.app.prog_type == ELF) {
				printf("    #include <cap-ng.h>\n");
				printf("    #include <stdio.h>\n");
				printf("    #include <stdlib.h>\n");
				printf("    ...\n");
				printf("    capng_clear(CAPNG_SELECT_BOTH);\n");
				print_updatev_wrapped("    capng_updatev(CAPNG_ADD, "
						      "CAPNG_EFFECTIVE|CAPNG_PERMITTED",
						      "", "-1);\n");
				printf("    if (capng_change_id(uid, gid, "
				       "CAPNG_DROP_SUPP_GRP | "
				       "CAPNG_CLEAR_BOUNDING)) {\n");
				printf("\tperror(\"capng_change_id\");\n");
				/* Failure can leave partial privileges. */
				printf("\texit(EXIT_FAILURE);\n");
				printf("    }\n\n");
			} else if (state.app.prog_type == PYTHON) {
				printf("    import sys\n");
				printf("    import _capng as capng\n");
				printf("    ...\n");
				printf("    capng.capng_clear(capng.CAPNG_SELECT_BOTH)\n");
				print_updatev_wrapped("    capng.capng_updatev("
						      "capng.CAPNG_ADD, "
						      "capng.CAPNG_EFFECTIVE|"
						      "capng.CAPNG_PERMITTED",
						      "capng.", "-1)\n");
				printf("    e = capng.capng_change_id(uid, gid, "
				       "capng.CAPNG_DROP_SUPP_GRP | "
				       "capng.CAPNG_CLEAR_BOUNDING)\n");
				printf("    if e < 0:\n");
				printf("\tprint(f\"Error: {e}\")\n");
				printf("\tsys.exit(1)\n\n");
			}
		}

		printf("  For systemd service:\n");
		if (state.capset_observed)
			print_wrapped_text("    Note: ",
					   "Ambient capabilities must include initialization requirements. The application drops to the operational set internally via capset.");
		printf("    [Service]\n");
		printf("    User=<non-root-user>\n");
		printf("    Group=<non-root-group>\n");
		printf("    AmbientCapabilities=");
		first = 1;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_required_union(&state.app.checks[i]) &&
			    include_cap_in_recommendations(i)) {
				if (!first)
					printf(" ");
				printf("%s", cap_name_safe(i));
				first = 0;
			}
		}
		printf("\n");
		printf("    CapabilityBoundingSet=");
		first = 1;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_required_union(&state.app.checks[i]) &&
			    include_cap_in_recommendations(i)) {
				if (!first)
					printf(" ");
				printf("%s", cap_name_safe(i));
				first = 0;
			}
		}
		printf("\n\n");

		printf("  For file capabilities (via filecap):\n");
		if (state.capset_observed)
			print_wrapped_text("    Note: ",
					   "File capabilities must include initialization requirements. The application drops to the operational set internally via capset.");
		printf("    filecap /path/to/binary");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_required_union(&state.app.checks[i]) &&
			    include_cap_in_recommendations(i))
				printf(" %s", cap_name_safe(i));
		}
		printf("\n\n");

		printf("  For Docker/Podman:\n");
		if (state.capset_observed)
			print_wrapped_text("    Note: ",
					   "Container capabilities must include initialization requirements. The application drops to the operational set internally via capset.");
		printf("    docker run --user $(id -u):$(id -g) \\\n");
		printf("      --cap-drop=ALL \\\n");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_required_union(&state.app.checks[i]) &&
			    include_cap_in_recommendations(i))
				printf("      --cap-add=%s \\\n",
				       cap_name_safe(i));
		}
		printf("      your-image:tag\n\n");

		printf("  For Kubernetes:\n");
		if (state.capset_observed)
			print_wrapped_text("    Note: ",
					   "Container capabilities must include initialization requirements. The application drops to the operational set internally via capset.");
		printf("    securityContext:\n");
		printf("      runAsUser: 1000\n");
		printf("      runAsGroup: 1000\n");
		printf("      capabilities:\n");
		printf("        drop:\n");
		printf("          - ALL\n");
		printf("        add:\n");
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (cap_required_union(&state.app.checks[i]) &&
			    include_cap_in_recommendations(i))
				printf("          - %s\n", cap_name_safe(i));
		}
		printf("\n");
	} else {
		printf("RECOMMENDATIONS:\n");
		print_rule('-');
		print_wrapped_text("  ",
				   "This application does not require any elevated capabilities!");
		print_wrapped_text("  ",
				   "Run as an unprivileged user with no special capabilities.");
		printf("\n");
	}

	print_wrapped_text("EXPERIMENTAL NOTICE: ",
			   "cap-audit output is experimental, but very close.");
}
