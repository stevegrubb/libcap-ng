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

/* Ring buffer event processing: noise filtering
 * and per-capability accounting for observed checks.
 */

#include "cap_audit.h"
#include "proc-sanitize.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Only SETGID/SETUID checks need deferring, not an unbounded event history. */
struct keepcaps_checks {
	unsigned long granted;
	unsigned long denied;
	int first_granted_syscall;
};

struct keepcaps_window {
	struct keepcaps_window *next;
	__u32 pid;
	__u32 tid;
	__u64 granted_caps;
	/* Indexed by capability - CAP_SETGID (SETGID=6, SETUID=7). */
	struct keepcaps_checks checks[2];
};

/* Return the link owning this thread's window, or the empty tail link. */
static struct keepcaps_window **find_keepcaps_window(const struct cap_event *e)
{
	struct keepcaps_window **link = &state.keepcaps_windows;

	while (*link && ((*link)->pid != e->pid || (*link)->tid != e->tid))
		link = &(*link)->next;
	return link;
}

/*
 * Commit deferred checks as initialization only for a completed pair.
 * Without the closing prctl, keep the original operational classification:
 * a daemon may intentionally leave KEEPCAPS set while doing normal work.
 */
static void finish_keepcaps_window(struct keepcaps_window **link, bool complete)
{
	struct keepcaps_window *window = *link;
	int cap;

	if (complete)
		state.keepcaps_init_caps |= window->granted_caps;
	else {
		state.keepcaps_incomplete = true;
		fprintf(stderr, "Warning: PID %u TID %u enabled "
			"PR_SET_KEEPCAPS, but no successful disable was observed "
			"before exec, exit, or the end of tracing; retaining "
			"the original capability classification.\n",
			window->pid, window->tid);
	}
	for (cap = CAP_SETGID; cap <= CAP_SETUID; cap++) {
		struct cap_check *check = &state.app.checks[cap];
		const struct keepcaps_checks *pending =
			&window->checks[cap - CAP_SETGID];

		if (complete) {
			check->count += pending->granted + pending->denied;
			check->granted += pending->granted;
			check->denied += pending->denied;
			if (pending->granted && !check->needed) {
				check->needed = 1;
				update_reason_to(&check->reason,
						 pending->first_granted_syscall);
			}
		} else {
			check->op_count += pending->granted + pending->denied;
			check->op_granted += pending->granted;
			check->op_denied += pending->denied;
			if (pending->granted && !check->op_needed) {
				check->op_needed = 1;
				update_reason_to(&check->op_reason,
						 pending->first_granted_syscall);
			}
		}
	}
	*link = window->next;
	free(window);
}

/* Track successful flag changes, not nested calls or another thread's flag. */
static void handle_keepcaps(const struct cap_event *e)
{
	struct keepcaps_window **link;

	if (e->syscall_ret != 0 || e->keepcaps > 1)
		return;
	link = find_keepcaps_window(e);
	if (e->keepcaps) {
		if (*link)
			return;
		*link = calloc(1, sizeof(**link));
		if (!*link) {
			state.keepcaps_incomplete = true;
			state.observation.userspace_failures++;
			fprintf(stderr, "Warning: unable to track KEEPCAPS "
				"transition for PID %u TID %u\n", e->pid, e->tid);
			return;
		}
		(*link)->pid = e->pid;
		(*link)->tid = e->tid;
	} else if (*link)
		finish_keepcaps_window(link, true);
}

/*
 * Match credential-changing syscalls, including legacy 32-bit ID variants.
 * SETUID/SETGID checks from unrelated operations within the window must not
 * be relabeled. libcap-ng closes KEEPCAPS before its final capset, so this
 * bracket identifies ID changes, not the exact final capability-drop point.
 */
static int is_id_change(const struct cap_event *e)
{
	static const char *const uid_calls[] = {
		"setuid", "setreuid", "setresuid", "setfsuid",
	};
	static const char *const gid_calls[] = {
		"setgid", "setregid", "setresgid", "setfsgid", "setgroups",
	};
	const char *const *calls;
	const char *name;
	size_t count, i;

	if (e->capability == CAP_SETUID) {
		calls = uid_calls;
		count = sizeof(uid_calls) / sizeof(uid_calls[0]);
	} else if (e->capability == CAP_SETGID) {
		calls = gid_calls;
		count = sizeof(gid_calls) / sizeof(gid_calls[0]);
	} else
		return 0;
	name = syscall_name_from_nr(e->syscall_nr);
	if (!name)
		return 0;
	for (i = 0; i < count; i++) {
		size_t len = strlen(calls[i]);

		if (!strncmp(name, calls[i], len) &&
		    (!name[len] || !strcmp(name + len, "32")))
			return 1;
	}
	return 0;
}

/* Flush unmatched windows before any output format consumes the counters. */
void finish_cap_events(void)
{
	while (state.keepcaps_windows)
		finish_keepcaps_window(&state.keepcaps_windows, false);
}

static int is_always_noise(const struct cap_event *e)
{
	/* Exec credential transitions are independent of application work. */
	if (e->syscall_nr == state.app.execve_nr &&
	   (e->capability == CAP_SYS_ADMIN ||
	    e->capability == CAP_SETPCAP))
		return 1;

	/*
	 * cap_vm_enough_memory probes SYS_ADMIN for overcommit accounting,
	 * including during interpreter shutdown. NOAUDIT alone is not enough:
	 * enforcement checks also use it, so retain the syscall/capability match.
	 */
	if ((e->cap_opts & CAP_OPT_NOAUDIT) &&
	    e->capability == CAP_SYS_ADMIN &&
	    (e->syscall_nr == state.app.brk_nr ||
	     e->syscall_nr == state.app.mmap_nr ||
	     e->syscall_nr == state.app.mprotect_nr ||
	     e->syscall_nr == state.app.mremap_nr))
		return 1;

	return 0;
}

static void add_denied_syscall(struct cap_check *check, int syscall_nr)
{
	size_t i;
	int *tmp;
	size_t new_cap;

	for (i = 0; i < check->denied_syscall_count; i++) {
		if (check->denied_syscalls[i] == syscall_nr)
			return;
	}

	if (check->denied_syscall_count == check->denied_syscall_capacity) {
		new_cap = check->denied_syscall_capacity ?
			  check->denied_syscall_capacity * 2 : 4;
		tmp = realloc(check->denied_syscalls, new_cap * sizeof(int));
		if (!tmp) {
			state.observation.userspace_failures++;
			return;
		}
		check->denied_syscalls = tmp;
		check->denied_syscall_capacity = new_cap;
	}

	check->denied_syscalls[check->denied_syscall_count++] = syscall_nr;
}

static int check_has_denied_syscall(const struct cap_check *check,
				    int syscall_nr)
{
	size_t i;

	for (i = 0; i < check->denied_syscall_count; i++) {
		if (check->denied_syscalls[i] == syscall_nr)
			return 1;
	}
	return 0;
}

static void handle_syscall_result(const struct cap_event *e)
{
	int cap;

	for (cap = 0; cap <= CAP_LAST_CAP && cap < 64; cap++) {
		struct cap_check *check;

		if (!(e->denied_caps & (1ULL << cap)))
			continue;
		check = &state.app.checks[cap];
		/* Ignore outcomes for capability events filtered by userspace. */
		if (!check_has_denied_syscall(check, e->syscall_nr))
			continue;
		if (add_cap_syscall_outcome(check, e->syscall_nr,
					    e->syscall_ret) != 0) {
			state.observation.userspace_failures++;
			fprintf(stderr,
				"Warning: unable to record syscall outcome\n");
		}
	}

	if (state.verbose)
		fprintf(stderr, "[SYSCALL] pid=%u syscall=%s return=%lld "
		       "denied_caps=0x%llx\n", e->pid,
		       syscall_name_from_nr(e->syscall_nr) ?: "unknown",
		       (long long)e->syscall_ret,
		       (unsigned long long)e->denied_caps);
}

/* Mark the first authenticated successful capset as the phase boundary. */
static void observe_initial_capset(const struct cap_event *e)
{
	/* CAP_EVENT_CAPSET is emitted only after cap_capset authenticated the
	 * call and the syscall returned success. Its raw number is ABI-relative,
	 * so userspace must not reclassify the event using the native ABI table.
	 */
	if (state.capset_observed || e->pid != (__u32)state.app.pid)
		return;

	state.capset_observed = 1;
	if (state.verbose)
		fprintf(stderr, "[CAP] Capability drop detected (capset from "
		       "initial PID); switching to operational phase\n");
}

/*
 * Child requests also constrain the inherited deployment boundary, but only
 * the initial process's capset separates its initialization and operation.
 */
static void handle_capset_result(const struct cap_event *e)
{
	if (e->syscall_ret != 0)
		return;
	/* A child can install sets inside a different user namespace. Those
	 * bits cannot justify grants in the auditor's namespace.
	 */
	if (!e->targ_ns_inum)
		state.unknown_target_ns_observed = true;
	else if (e->targ_ns_inum != state.baseline_user_ns_inum)
		state.foreign_target_ns_observed = true;

	record_successful_capset(e);
	observe_initial_capset(e);

	if (state.verbose)
		fprintf(stderr, "[CAPSET] pid=%u effective=0x%llx permitted=0x%llx "
		       "inheritable=0x%llx\n", e->pid,
		       (unsigned long long)e->capset_effective,
		       (unsigned long long)e->capset_permitted,
		       (unsigned long long)e->capset_inheritable);
}

int handle_cap_event(void *ctx __attribute__((unused)), void *data,
		     size_t data_sz __attribute__((unused)))
{
	const struct cap_event *e = data;
	int op_phase = state.capset_observed;

	if (e->event_type == CAP_EVENT_KEEPCAPS) {
		handle_keepcaps(e);
		return 0;
	}
	if (e->event_type == CAP_EVENT_TASK_END) {
		struct keepcaps_window **link = find_keepcaps_window(e);

		if (*link)
			finish_keepcaps_window(link, false);
		return 0;
	}
	if (e->event_type == CAP_EVENT_SYSCALL_RESULT) {
		handle_syscall_result(e);
		return 0;
	}
	if (e->event_type == CAP_EVENT_CAPSET) {
		handle_capset_result(e);
		return 0;
	}
	if (e->event_type != CAP_EVENT_CHECK)
		return 0;

	if (is_always_noise(e)) {
		if (state.verbose) {
			if (e->syscall_nr == state.app.execve_nr)
				fprintf(stderr, "[CAP] Filtered exec noise: "
				       "cap=%s syscall=%s\n",
				       cap_name_safe(e->capability),
				       syscall_name_from_nr(e->syscall_nr) ?:
				       "unknown");
			else
				fprintf(stderr, "[CAP] Filtered advisory check: "
				       "cap=%s syscall=%s (CAP_OPT_NOAUDIT)\n",
				       cap_name_safe(e->capability),
				       syscall_name_from_nr(e->syscall_nr) ?:
				       "unknown");
		}
		return 0;
	}

	/*
	 * A target namespace does not identify the namespace that scoped the
	 * checked credentials. Do not turn an ambiguous observation into a
	 * potentially broader capability grant.
	 */
	if (e->targ_ns_inum != 0 && state.baseline_user_ns_inum != 0 &&
	    e->targ_ns_inum != state.baseline_user_ns_inum)
		state.foreign_target_ns_observed = true;
	if (!e->targ_ns_inum)
		state.unknown_target_ns_observed = true;

	if (state.verbose) {
		char comm[sizeof(e->comm) + 1];
		char *safe_comm;

		memcpy(comm, e->comm, sizeof(e->comm));
		comm[sizeof(e->comm)] = 0;
		safe_comm = sanitize_untrusted_field(comm);
		fprintf(stderr, "[CAP] pid=%d cap=%s result=%s syscall=%s "
		       "comm=%s\n",
		       e->pid, cap_name_safe(e->capability),
		       e->result ? "GRANTED" : "DENIED",
		       syscall_name_from_nr(e->syscall_nr) ?: "unknown",
		       safe_comm ? safe_comm : "[unavailable]");
		free(safe_comm);
	}

	/*
	 * The BPF cap_capset probe proved that new I fits within old I | P,
	 * so this SETPCAP check only selects an optional privilege shortcut.
	 * Keep phase detection and namespace diagnostics above; successful
	 * capset payloads still independently constrain deployment sets.
	 * Do not suppress other SETPCAP uses or infer this from file xattrs.
	 */
	if (e->capability == CAP_SETPCAP && e->capset_inh_optional) {
		if (state.verbose)
			fprintf(stderr, "[CAP] Optional SETPCAP check in capset; "
			       "inheritable change does not require it\n");
		return 0;
	}

	if (e->capability >= 0 && e->capability <= CAP_LAST_CAP) {
		struct cap_check *check;
		struct keepcaps_window *window = NULL;

		check = &state.app.checks[e->capability];
		check->capability = e->capability;
		/* Keep denial/outcome evidence even while phase accounting waits. */
		if (e->result == 0)
			add_denied_syscall(check, e->syscall_nr);
		if (state.keepcaps_windows && is_id_change(e))
			window = *find_keepcaps_window(e);
		if (window && e->result > 0)
			window->granted_caps |= 1ULL << e->capability;
		if (window && op_phase) {
			struct keepcaps_checks *pending =
				&window->checks[e->capability - CAP_SETGID];

			if (e->result > 0) {
				if (!pending->granted)
					pending->first_granted_syscall = e->syscall_nr;
				pending->granted++;
			} else if (e->result == 0)
				pending->denied++;
			return 0;
		}

		if (op_phase) {
			check->op_count++;
			if (e->result > 0)
				check->op_granted++;
			else if (e->result == 0)
				check->op_denied++;
			if (e->result > 0 && check->op_needed != 1) {
				check->op_needed = 1;
				update_reason_to(&check->op_reason, e->syscall_nr);
			}
		} else {
			check->count++;
			if (e->result > 0)
				check->granted++;
			else if (e->result == 0)
				check->denied++;

			if (e->result > 0 && check->needed != 1) {
				check->needed = 1;
				update_reason_to(&check->reason, e->syscall_nr);
			}
		}
	}

	return 0;
}
