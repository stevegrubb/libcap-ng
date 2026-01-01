// SPDX-License-Identifier: LGPL-2.1-or-later
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
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

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

struct cap_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	int capability;
	int result;
	int syscall_nr;
	char comm[TASK_COMM_LEN];
	__u64 stack_id;
	__u32 targ_ns_inum;
};

struct cap_stats {
	__u64 checks;
	__u64 granted;
	__u64 denied;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
	__uint(max_entries, 1024);
} target_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} cap_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
	__uint(max_entries, 10000);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cap_stats);
	__uint(max_entries, 64);
} capability_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct cap_event);
	__uint(max_entries, 1024);
} cap_events_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, int);
	__uint(max_entries, 4096);
} current_syscalls SEC(".maps");

static __always_inline int should_trace_pid(__u32 pid)
{
	__u8 *trace;

	trace = bpf_map_lookup_elem(&target_pids, &pid);
	return trace ? 1 : 0;
}

static __always_inline void record_stats(int cap)
{
	__u32 key;
	struct cap_stats *stats;

	if (cap < 0 || cap >= 64)
		return;

	key = (__u32)cap;
	stats = bpf_map_lookup_elem(&capability_stats, &key);
	if (stats)
		__sync_fetch_and_add(&stats->checks, 1);
	else {
		struct cap_stats new_stats = { 0 };

		new_stats.checks = 1;
		bpf_map_update_elem(&capability_stats, &key, &new_stats,
				    BPF_ANY);
	}
}

static __always_inline void update_result_stats(int cap, int ret)
{
	__u32 key;
	struct cap_stats *stats;

	if (cap < 0 || cap >= 64)
		return;

	key = (__u32)cap;
	stats = bpf_map_lookup_elem(&capability_stats, &key);
	if (!stats)
		return;

	if (!ret)
		__sync_fetch_and_add(&stats->granted, 1);
	else
		__sync_fetch_and_add(&stats->denied, 1);
}

static __always_inline int read_syscall(struct pt_regs *ctx)
{
	__u64 pid_tgid;
	int *nr;

	pid_tgid = bpf_get_current_pid_tgid();
	nr = bpf_map_lookup_elem(&current_syscalls, &pid_tgid);
	if (nr)
		return *nr;

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

static __always_inline void fill_event_common(struct cap_event *ev,
					      struct pt_regs *ctx, int cap)
{
	__u64 pid_tgid;
	__u64 uid_gid;

	pid_tgid = bpf_get_current_pid_tgid();
	ev->pid = pid_tgid >> 32;
	ev->tid = (__u32)pid_tgid;
	ev->capability = cap;
	ev->timestamp_ns = bpf_ktime_get_ns();

	uid_gid = bpf_get_current_uid_gid();
	ev->uid = uid_gid >> 32;
	ev->gid = (__u32)uid_gid;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	ev->syscall_nr = read_syscall(ctx);
	ev->stack_id = bpf_get_stackid(ctx, &stack_traces,
				       BPF_F_USER_STACK);
}

static __always_inline void stash_event(struct cap_event *ev)
{
	__u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&cap_events_inflight, &pid_tgid, ev,
			    BPF_ANY);
}

static __always_inline int submit_event(int ret)
{
	__u64 pid_tgid;
	struct cap_event *stored;
	struct cap_event *out;

	pid_tgid = bpf_get_current_pid_tgid();
	stored = bpf_map_lookup_elem(&cap_events_inflight, &pid_tgid);
	if (!stored)
		return 0;

	out = bpf_ringbuf_reserve(&cap_events, sizeof(*out), 0);
	if (!out)
		goto cleanup;

	__builtin_memcpy(out, stored, sizeof(*out));
	out->result = ret ? 0 : 1;

	bpf_ringbuf_submit(out, 0);

cleanup:
	bpf_map_delete_elem(&cap_events_inflight, &pid_tgid);
	return 0;
}

static __always_inline int handle_capable(struct pt_regs *ctx, int cap,
					  struct user_namespace *targ_ns)
{
	struct cap_event ev = { 0 };
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (!should_trace_pid(pid))
		return 0;

	record_stats(cap);
	fill_event_common(&ev, ctx, cap);

	if (targ_ns) {
		struct ns_common *ns;

		ns = (struct ns_common *)targ_ns;
		ev.targ_ns_inum = BPF_CORE_READ(ns, inum);
	}

	stash_event(&ev);
	return 0;
}

SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable, const struct cred *cred,
	       struct user_namespace *targ_ns, int cap, unsigned int opts)
{
	return handle_capable(ctx, cap, targ_ns);
}

SEC("kretprobe/cap_capable")
int BPF_KRETPROBE(trace_cap_capable_ret, int ret)
{
	__u64 pid_tgid;
	struct cap_event *stored;

	pid_tgid = bpf_get_current_pid_tgid();
	stored = bpf_map_lookup_elem(&cap_events_inflight, &pid_tgid);
	if (stored)
		update_result_stats(stored->capability, ret);

	return submit_event(ret);
}

SEC("kprobe/ns_capable")
int BPF_KPROBE(trace_ns_capable, struct user_namespace *ns, int cap)
{
	return handle_capable(ctx, cap, ns);
}

SEC("kretprobe/ns_capable")
int BPF_KRETPROBE(trace_ns_capable_ret, int ret)
{
	return submit_event(ret);
}

SEC("kprobe/ns_capable_noaudit")
int BPF_KPROBE(trace_ns_capable_noaudit, struct user_namespace *ns, int cap)
{
	return handle_capable(ctx, cap, ns);
}

SEC("kretprobe/ns_capable_noaudit")
int BPF_KRETPROBE(trace_ns_capable_noaudit_ret, int ret)
{
	return submit_event(ret);
}

SEC("kprobe/capable")
int BPF_KPROBE(trace_capable, int cap)
{
	return handle_capable(ctx, cap, NULL);
}

SEC("kretprobe/capable")
int BPF_KRETPROBE(trace_capable_ret, int ret)
{
	return submit_event(ret);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid;
	__u32 pid;
	__u32 id;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (!should_trace_pid(pid))
		return 0;

	id = ctx->id;
	bpf_map_update_elem(&current_syscalls, &pid_tgid, &id, BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid;
	__u32 pid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	if (!should_trace_pid(pid))
		return 0;

	bpf_map_delete_elem(&current_syscalls, &pid_tgid);
	return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u8 val = 1;
	__u32 parent_pid;
	__u32 child_pid;

	parent_pid = ctx->parent_pid;
	child_pid = ctx->child_pid;

	if (should_trace_pid(parent_pid))
		bpf_map_update_elem(&target_pids, &child_pid, &val, BPF_ANY);

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 pid;

	pid = ctx->pid;
	bpf_map_delete_elem(&target_pids, &pid);

	return 0;
}
