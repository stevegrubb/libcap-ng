// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cap_audit.bpf.c - Capture capability checks for a target application
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

#ifdef __clang__
/*
 * bpftool can emit nameless BTF declarations in vmlinux.h. Clang warns about
 * those generated declarations even though this program does not use them.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#endif
#include "vmlinux.h"
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifndef CAP_OPT_NOAUDIT
#define CAP_OPT_NOAUDIT 2
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define CAP_SETPCAP	8
#define PR_SET_KEEPCAPS	8

/* Linux used this named u32[2] type for capabilities before 6.3. A concrete
 * flavored type is required because CO-RE does not match a forward declaration
 * to the target's struct. Its existence distinguishes the two big-endian
 * representations without tying the build to either kernel layout.
 */
#ifdef __BPF__
#define CAP_AUDIT_PRESERVE_ACCESS_INDEX \
	__attribute__((preserve_access_index))
#else
#define CAP_AUDIT_PRESERVE_ACCESS_INDEX
#endif
struct kernel_cap_struct___old {
	__u32 cap[2];
} CAP_AUDIT_PRESERVE_ACCESS_INDEX;
#undef CAP_AUDIT_PRESERVE_ACCESS_INDEX

const volatile int prctl_syscall_nr = -1;

/*
 * BPF overview:
 * The BPF side attaches to cap_capable and syscall tracepoints to capture
 * capability checks only for a target process tree.
 *
 * The design challenge is noise filtering: distinguish capability checks
 * caused by the target application from kernel-internal checks running under
 * the same PID. The first filtering layer lives entirely in this BPF program
 * and is encoded in target_pids map values, keyed by thread ID (TID).
 * Using TIDs throughout lets surviving threads keep tracing after their
 * group leader exits, and matches the IDs supplied by sched_process_fork.
 *
 * target_pids values are phases, not just booleans:
 *   0 = not traced
 *   1 = pre-exec (PID registered, but exec transition not complete)
 *   2 = post-exec (target image is running; capability events are recordable)
 *
 * Phase 1 suppresses all capability events for the initial child so checks
 * between fork() and execve() are dropped. That removes pre-exec noise such
 * as DAC_READ_SEARCH from PATH traversal while resolving the target binary.
 *
 * The transition point is sched_process_exec. That tracepoint fires in
 * begin_new_exec() after the point-of-no-return where the old image is gone
 * and the new executable is committed. This is a kernel-level signal, so it
 * works regardless of libc/toolchain choice (glibc, musl, static, scripts).
 *
 * Fork inherits the parent's phase value. Children of an already running
 * target (phase 2) begin recording immediately, while children spawned before
 * the initial exec remain in phase 1 until their own exec transition.
 *
 * raw_syscalls/sys_enter and sys_exit use should_trace_tid() (phase > 0)
 * so syscall context and completion results are available the instant the
 * exec gate opens.
 * Capability hooks use should_record_tid() (phase >= 2), so only post-exec
 * capability checks are emitted.
 *
 * For traced tasks, the program builds cap_event records with task identity,
 * syscall context, namespace inode, the CAP_OPT_* flags passed to
 * cap_capable(), and streams finalized events through a ring buffer. A syscall
 * completion event correlates denied checks from one invocation with its raw
 * kernel return value. Successful capset completion events also carry the
 * kernel-installed masks so userspace can distinguish a current-binary
 * compatibility constraint from confirmed capability use. The cap_opts field
 * carries the CAP_OPT_* flags so userspace can identify known advisory call
 * sites without treating CAP_OPT_NOAUDIT as a standalone filter.
 * CAP_OPT_NOAUDIT means "do not audit" and is only a confirming signal
 * alongside syscall and capability matching. Fork/exit tracepoints keep the
 * PID filter in sync so children are traced and exits are pruned.
 */

#if !defined(__TARGET_ARCH_x86) && !defined(__TARGET_ARCH_arm64) && \
	!defined(__TARGET_ARCH_arm) && !defined(__TARGET_ARCH_powerpc) && \
	!defined(__TARGET_ARCH_s390) && !defined(__TARGET_ARCH_riscv) && \
	!defined(__TARGET_ARCH_mips) && !defined(__TARGET_ARCH_loongarch)
#if defined(__x86_64__) || defined(__i386__)
#define __TARGET_ARCH_x86
#elif defined(__aarch64__)
#define __TARGET_ARCH_arm64
#elif defined(__arm__)
#define __TARGET_ARCH_arm
#elif defined(__powerpc__)
#define __TARGET_ARCH_powerpc
#elif defined(__s390x__) || defined(__s390__)
#define __TARGET_ARCH_s390
#elif defined(__riscv)
#define __TARGET_ARCH_riscv
#elif defined(__mips__)
#define __TARGET_ARCH_mips
#elif defined(__loongarch64)
#define __TARGET_ARCH_loongarch
#else
#define __TARGET_ARCH_x86
#endif
#endif

char LICENSE[] SEC("license") = "GPL";

enum cap_event_type {
	CAP_EVENT_CHECK,
	CAP_EVENT_SYSCALL_RESULT,
	CAP_EVENT_CAPSET,
	CAP_EVENT_KEEPCAPS,
	CAP_EVENT_TASK_END,
};

struct cap_event {
	__u32 pid;
	int capability;
	int result;
	int syscall_nr;
	char comm[TASK_COMM_LEN];
	__u32 targ_ns_inum;
	__u32 cap_opts;
	__s64 syscall_ret;
	__u64 denied_caps;
	__u64 capset_effective;
	__u64 capset_permitted;
	__u64 capset_inheritable;
	__u32 event_type;
	__u32 capset_inh_optional;
	__u32 tid;
	__u32 keepcaps;
};

// This sets the limit for how many tasks (including threads) can be traced.
// Because of this limit, the tracer may not be suitable for shell
// scripts or long running process that fork child handlers that
// terminate soon after launching. When this fills up, no more
// children will be traced. This is the breaking point for long
// running apps. The other limits aren't as likely to be broken.
// This is approx 16 bytes per entry. (Default uses 128K of memory)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 8192);
} target_pids SEC(".maps");

// This declares the size of the ring buf that holds events for
// userspace to access.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} cap_events SEC(".maps");

/* Pair capability entry and return probes by thread. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct cap_event);
	__uint(max_entries, 1024);
} cap_events_inflight SEC(".maps");

/* Syscall state is removed on syscall completion or task exit. Non-leader
 * exec moves it to the new TID so post-exec checks keep their attribution.
 */
struct syscall_state {
	__u64 denied_caps;
	__u64 capset_optional_cred;
	int nr;
	__u8 record_capset;
	__u8 keepcaps_valid;
	__u8 keepcaps;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct syscall_state);
	__uint(max_entries, 4096);
} current_syscalls SEC(".maps");

static __always_inline int get_tid_phase(__u32 tid)
{
	__u8 *val = bpf_map_lookup_elem(&target_pids, &tid);

	return val ? *val : 0;
}

/*
 * should_trace_tid - check if the current thread is in the target set.
 * @tid: thread ID of the current task.
 *
 * Looks up the TID in target_pids and returns 1 when tracing is enabled for
 * it, otherwise 0.
 */
static __always_inline int should_trace_tid(__u32 tid)
{
	return get_tid_phase(tid) > 0;
}

/*
 * should_record_tid - check if the current thread is post-exec.
 * @tid: thread ID of the current task.
 *
 * Returns 1 for threads whose process has completed exec.
 */
static __always_inline int should_record_tid(__u32 tid)
{
	return get_tid_phase(tid) >= 2;
}

/*
 * read_syscall - fetch the syscall number for the current task.
 * @ctx: pt_regs provided by the kprobe.
 *
 * Uses a per-thread map populated by sys_enter tracepoints when available,
 * and falls back to architecture-specific pt_regs fields. Returns the syscall
 * number or -1 when it cannot be determined.
 */
static __always_inline int read_syscall(struct pt_regs *ctx)
{
	__u64 pid_tgid;
	struct syscall_state *syscall;

	pid_tgid = bpf_get_current_pid_tgid();
	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (syscall)
		return syscall->nr;

#ifdef __TARGET_ARCH_x86
	return BPF_CORE_READ(ctx, orig_ax);
#elif defined(__TARGET_ARCH_arm64)
	return BPF_CORE_READ(ctx, syscallno);
#elif defined(__TARGET_ARCH_powerpc)
	return BPF_CORE_READ(ctx, gpr[0]);
#elif defined(__TARGET_ARCH_s390)
	return BPF_CORE_READ(ctx, gprs[2]);
#else
	return -1;
#endif
}

/* Record a denied check against the syscall invocation that contained it. */
static __always_inline void mark_syscall_denial(int cap)
{
	struct syscall_state *syscall;
	__u64 pid_tgid;

	if (cap < 0 || cap >= 64)
		return;

	pid_tgid = bpf_get_current_pid_tgid();
	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (syscall)
		syscall->denied_caps |= 1ULL << cap;
}

/*
 * cap_capset() checks SETPCAP through cap_inh_is_capped() even when the
 * requested inheritable set is already allowed without that capability.
 * A granted probe in that case is not a deployment requirement. Identify
 * it from the kernel's copied arguments, not a racy userspace snapshot or
 * the initial executable's file xattr (children may use different caps).
 *
 * Keep the observation unless all reads succeed and new I is a subset of
 * old I | old P. Compare opaque storage: the same bitwise subset test works
 * for both kernel_cap_t layouts (u32[2] and u64), on either endianness.
 * The return probe bounds this annotation to this thread's cap_capset call.
 */
SEC("kprobe/cap_capset")
int BPF_KPROBE(trace_cap_capset, struct cred *new,
	       const struct cred *old, const kernel_cap_t *effective,
	       const kernel_cap_t *inheritable)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_state *syscall;
	__u64 new_i, old_i, old_p;

	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (!syscall)
		return 0;
	/* cap_capset is the ABI-independent identity check. Raw syscall numbers
	 * differ between native and compat ABIs, while an unrelated compat call
	 * can share the native number. Only this hook can set the marker; syscall
	 * exit still proves that the authenticated capset completed successfully.
	 */
	if (should_record_tid((__u32)pid_tgid))
		syscall->record_capset = 1;
	syscall->capset_optional_cred = 0;
	if (bpf_core_type_size(kernel_cap_t) != sizeof(new_i) ||
	    bpf_probe_read_kernel(&new_i, sizeof(new_i), inheritable) ||
	    bpf_core_read(&old_i, sizeof(old_i), &old->cap_inheritable) ||
	    bpf_core_read(&old_p, sizeof(old_p), &old->cap_permitted))
		return 0;
	if ((new_i & ~(old_i | old_p)) == 0)
		syscall->capset_optional_cred = (__u64)old;
	return 0;
}

SEC("kretprobe/cap_capset")
int BPF_KRETPROBE(trace_cap_capset_ret, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_state *syscall;

	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (syscall)
		syscall->capset_optional_cred = 0;
	return 0;
}

/*
 * Observe cap_capable only: capable and ns_capable wrappers reach this
 * common hook and would overwrite the same per-thread in-flight event.
 * Their boolean return values also have the opposite meaning to its errno.
 */
SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable, const struct cred *cred,
	       struct user_namespace *targ_ns, int cap, unsigned int opts)
{
	struct cap_event ev = { 0 };
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_state *syscall;

	ev.pid = pid_tgid >> 32;
	ev.tid = (__u32)pid_tgid;
	if (!should_record_tid(ev.tid))
		return 0;

	ev.capability = cap;
	ev.cap_opts = opts;
	ev.syscall_nr = read_syscall(ctx);
	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (cap == CAP_SETPCAP && syscall && syscall->capset_optional_cred &&
	    syscall->capset_optional_cred == (__u64)cred &&
	    targ_ns == BPF_CORE_READ(cred, user_ns))
		ev.capset_inh_optional = 1;
	bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
	/* ns is embedded within user_namespace, not its first member. */
	if (targ_ns)
		ev.targ_ns_inum = BPF_CORE_READ(targ_ns, ns.inum);
	bpf_map_update_elem(&cap_events_inflight, &pid_tgid, &ev, BPF_ANY);
	return 0;
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(trace_cap_capable_ret, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct cap_event *stored;
	struct cap_event *out;

	stored = bpf_map_lookup_elem(&cap_events_inflight, &pid_tgid);
	if (!stored)
		return 0;

	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		goto cleanup;

	__builtin_memcpy(out, stored, sizeof(*out));
	out->result = ret ? 0 : 1;
	if (ret && !out->capset_inh_optional)
		mark_syscall_denial(stored->capability);

	bpf_ringbuf_submit(out, 0);

cleanup:
	bpf_map_delete_elem(&cap_events_inflight, &pid_tgid);
	return 0;
}

/*
 * trace_sys_enter - remember syscall numbers on entry.
 * @ctx: raw_syscalls/sys_enter tracepoint context.
 *
 * Stores the syscall number in a per-thread map for later lookup by the
 * capability probes. No-op for non-traced PIDs. Returns 0.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct syscall_state syscall = { 0 };
	__u64 pid_tgid;
	__u32 tid;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	if (!should_trace_tid(tid))
		return 0;

	syscall.nr = ctx->id;
	if (should_record_tid(tid) && ctx->id == prctl_syscall_nr &&
	    (int)ctx->args[0] == PR_SET_KEEPCAPS && ctx->args[1] <= 1) {
		syscall.keepcaps_valid = 1;
		syscall.keepcaps = ctx->args[1];
	}
	bpf_map_update_elem(&current_syscalls, &pid_tgid, &syscall, BPF_ANY);
	return 0;
}

/* Convert two native-endian words into the userspace capability numbering.
 * @words: words read from kernel_cap_t storage.
 * @legacy_layout: nonzero for the pre-6.3 u32[2] kernel layout.
 * @big_endian: nonzero when the BPF target is big endian.
 *
 * Returns a canonical 64-bit capability mask.
 */
static __always_inline __u64 cap_words_to_mask(const __u32 words[2],
						int legacy_layout,
						int big_endian)
{
	if (big_endian && !legacy_layout)
		return ((__u64)words[0] << 32) | words[1];
	return words[0] | ((__u64)words[1] << 32);
}

/* Convert a copied kernel capability set into userspace bit numbering.
 * @cap: capability value already read with a CO-RE field relocation.
 *
 * Returns a canonical 64-bit capability mask.
 */
static __always_inline __u64 kernel_cap_to_mask(const kernel_cap_t *cap)
{
	__u32 words[2];

	__builtin_memcpy(words, cap, sizeof(words));

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return cap_words_to_mask(words,
		bpf_core_type_exists(struct kernel_cap_struct___old), 1);
#else
	return cap_words_to_mask(words, 0, 0);
#endif
}

/* Read the capability sets committed to the current thread.
 * @effective: destination for the installed effective set.
 * @permitted: destination for the installed permitted set.
 * @inheritable: destination for the installed inheritable set.
 *
 * Returns 0 only when all sets came from the current immutable credentials.
 */
static __always_inline int read_current_capsets(__u64 *effective,
					 __u64 *permitted,
					 __u64 *inheritable)
{
	struct task_struct *task;
	const struct cred *cred;
	kernel_cap_t installed_effective;
	kernel_cap_t installed_permitted;
	kernel_cap_t installed_inheritable;

	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return -1;
	cred = BPF_CORE_READ(task, cred);
	if (!cred)
		return -1;

	if (bpf_core_type_size(kernel_cap_t) != sizeof(installed_effective))
		return -1;
	if (bpf_core_read(&installed_effective, sizeof(installed_effective),
			  &cred->cap_effective) ||
	    bpf_core_read(&installed_permitted, sizeof(installed_permitted),
			  &cred->cap_permitted) ||
	    bpf_core_read(&installed_inheritable, sizeof(installed_inheritable),
			  &cred->cap_inheritable))
		return -1;

	*effective = kernel_cap_to_mask(&installed_effective);
	*permitted = kernel_cap_to_mask(&installed_permitted);
	*inheritable = kernel_cap_to_mask(&installed_inheritable);
	return 0;
}

static __always_inline void emit_syscall_result(
				const struct syscall_state *syscall, __s64 ret)
{
	struct cap_event *out;
	__u64 pid_tgid;

	if (syscall->denied_caps == 0)
		return;

	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		return;

	__builtin_memset(out, 0, sizeof(*out));
	pid_tgid = bpf_get_current_pid_tgid();
	out->pid = pid_tgid >> 32;
	out->syscall_nr = syscall->nr;
	out->syscall_ret = ret;
	out->denied_caps = syscall->denied_caps;
	out->event_type = CAP_EVENT_SYSCALL_RESULT;
	bpf_ringbuf_submit(out, 0);
}

/* Emit kernel-owned masks installed by a successful capset call. */
static __always_inline void emit_capset_result(
				const struct syscall_state *syscall, __s64 ret)
{
	struct cap_event *out;
	__u64 pid_tgid;
	__u64 effective, permitted, inheritable;

	if (!syscall->record_capset || ret != 0)
		return;
	/* No userspace runs between commit_creds() and this tracepoint. Reading
	 * the current thread's immutable credentials binds the success result to
	 * the exact masks the kernel installed, even if another thread races the
	 * original userspace buffer.
	 */
	if (read_current_capsets(&effective, &permitted, &inheritable))
		return;

	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		return;

	__builtin_memset(out, 0, sizeof(*out));
	pid_tgid = bpf_get_current_pid_tgid();
	out->pid = pid_tgid >> 32;
	out->syscall_nr = syscall->nr;
	out->syscall_ret = ret;
	out->capset_effective = effective;
	out->capset_permitted = permitted;
	out->capset_inheritable = inheritable;
	out->event_type = CAP_EVENT_CAPSET;
	bpf_ringbuf_submit(out, 0);
}

/* Report keepcaps completion; failed prctls must not change phase tracking. */
static __always_inline void emit_keepcaps_result(
				const struct syscall_state *syscall, __s64 ret)
{
	struct cap_event *out;
	__u64 pid_tgid;

	if (!syscall->keepcaps_valid)
		return;
	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		return;
	__builtin_memset(out, 0, sizeof(*out));
	pid_tgid = bpf_get_current_pid_tgid();
	out->pid = pid_tgid >> 32;
	out->tid = (__u32)pid_tgid;
	out->syscall_nr = syscall->nr;
	out->syscall_ret = ret;
	out->keepcaps = syscall->keepcaps;
	out->event_type = CAP_EVENT_KEEPCAPS;
	bpf_ringbuf_submit(out, 0);
}

/*
 * trace_sys_exit - emit denied-check outcomes and clear syscall tracking.
 * @ctx: raw_syscalls/sys_exit tracepoint context.
 *
 * Emits the raw return value when the invocation contained denied capability
 * checks. A successful capset also emits its kernel-installed masks.
 * Keepcaps prctls emit their result so userspace can pair credential
 * transitions.
 * Removes the per-thread state before returning 0.
 */
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct syscall_state *syscall;
	__u64 pid_tgid;
	__u32 tid;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	if (!should_trace_tid(tid))
		return 0;

	syscall = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (syscall) {
		emit_syscall_result(syscall, ctx->ret);
		emit_capset_result(syscall, ctx->ret);
		emit_keepcaps_result(syscall, ctx->ret);
	}
	bpf_map_delete_elem(&current_syscalls, &pid_tgid);
	return 0;
}

/*
 * trace_sched_process_fork - follow new child processes.
 * @ctx: sched_process_fork tracepoint data.
 *
 * When a traced parent forks, automatically add the child PID to the filter
 * map so subsequent capability checks are captured. Returns 0.
 */
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent_pid;
	__u32 child_pid;
	__u8 *parent_val;

	parent_pid = ctx->parent_pid;
	child_pid = ctx->child_pid;

	parent_val = bpf_map_lookup_elem(&target_pids, &parent_pid);
	if (parent_val) {
		__u8 child_val = *parent_val;

		bpf_map_update_elem(&target_pids, &child_pid, &child_val,
				    BPF_ANY);
	}

	return 0;
}

/* Do not pair keepcaps calls across exec, thread exit, or TID reuse. */
static __always_inline void emit_task_end(__u32 tid)
{
	struct cap_event *out;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!should_record_tid(tid))
		return;
	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		return;
	__builtin_memset(out, 0, sizeof(*out));
	out->pid = pid;
	out->tid = tid;
	out->event_type = CAP_EVENT_TASK_END;
	bpf_ringbuf_submit(out, 0);
}

/*
 * trace_sched_process_exec - mark a traced PID as post-exec.
 * @ctx: sched_process_exec tracepoint data.
 *
 * Transitions the PID from pre-exec (phase 1) to post-exec (phase 2) once
 * the new binary image is loaded.
 */
SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	__u32 old_tid = ctx->old_pid;
	__u8 *val;
	__u8 new_val = 2;

	/* A non-leader exec changes TID; close the old thread's window. */
	emit_task_end(old_tid);
	val = bpf_map_lookup_elem(&target_pids, &old_tid);
	if (!val)
		return 0;
	bpf_map_update_elem(&target_pids, &tid, &new_val, BPF_ANY);
	if (old_tid != tid) {
		__u64 old_key = (pid_tgid & 0xffffffff00000000ULL) | old_tid;
		struct syscall_state *syscall;

		/* Exec keeps the TGID but adopts the leader's TID. Preserve its
		 * syscall context for capability checks after this tracepoint.
		 */
		syscall = bpf_map_lookup_elem(&current_syscalls, &old_key);
		if (syscall)
			bpf_map_update_elem(&current_syscalls, &pid_tgid,
					    syscall, BPF_ANY);
		bpf_map_delete_elem(&current_syscalls, &old_key);
		bpf_map_delete_elem(&cap_events_inflight, &old_key);
		bpf_map_delete_elem(&target_pids, &old_tid);
	}

	return 0;
}

/*
 * trace_sched_process_exit - prune exited processes from the target set.
 * @ctx: unused sched_process_exit tracepoint data.
 *
 * Removes the exiting PID from the target_pids map to prevent stale entries.
 * Returns 0.
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;

	/* This tracepoint runs in the exiting task. Its payload is not always
	 * layout-compatible with sched_process_template, so use the helper.
	 */
	(void)ctx;
	emit_task_end(tid);
	/* exit and fatal signals need not reach the syscall-exit tracepoint. */
	bpf_map_delete_elem(&current_syscalls, &pid_tgid);
	bpf_map_delete_elem(&cap_events_inflight, &pid_tgid);
	bpf_map_delete_elem(&target_pids, &tid);

	return 0;
}
