// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise the BPF event path with host-side helper and kernel-type fixtures.
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CO-RE resolves real layouts at load time. Give ns a nonzero offset here
 * so a cast to ns_common cannot accidentally pass the namespace test.
 */
#define __VMLINUX_H__
#define TASK_COMM_LEN 16
struct ns_common { __u32 inum; };
struct user_namespace { __u64 prefix[3]; struct ns_common ns; };
typedef struct { __u64 val; } kernel_cap_t;
struct cred {
	struct user_namespace *user_ns;
	kernel_cap_t cap_inheritable, cap_permitted;
};
struct pt_regs { long orig_ax, syscallno, gpr[1], gprs[3]; };
struct trace_event_raw_sys_enter { long id; unsigned long args[6]; };
struct trace_event_raw_sys_exit { long ret; };
struct trace_event_raw_sched_process_fork { int parent_pid, child_pid; };
struct trace_event_raw_sched_process_exec { int pid, old_pid; };
struct trace_event_raw_sched_process_template { int pid; };

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static void *mock_lookup(const void *map, const void *key);
static long mock_update(const void *map, const void *key,
			const void *value, __u64 flags);
static long mock_delete(const void *map, const void *key);
static void *mock_reserve(const void *map, __u64 size, __u64 flags);
static void mock_submit(void *data, __u64 flags);
static __u64 current_task;

/* Keep the production functions; replace only kernel helper boundaries. */
#undef BPF_KPROBE
#undef BPF_KRETPROBE
#undef BPF_CORE_READ
#undef bpf_core_read
#undef bpf_core_type_size
#define BPF_KPROBE(name, ...) name(struct pt_regs *ctx, __VA_ARGS__)
#define BPF_KRETPROBE(name, ...) name(struct pt_regs *ctx, __VA_ARGS__)
#define BPF_CORE_READ(src, field) ((src)->field)
#define bpf_core_read(dst, size, src) (memcpy(dst, src, size), 0)
#define bpf_core_type_size(type) sizeof(type)
#define bpf_probe_read_kernel(dst, size, src) (memcpy(dst, src, size), 0)
#define bpf_probe_read_user(dst, size, src) (memcpy(dst, src, size), 0)
#define bpf_get_current_pid_tgid() current_task
#define bpf_get_current_comm(dst, size) memset(dst, 0, size)
#define bpf_map_lookup_elem mock_lookup
#define bpf_map_update_elem mock_update
#define bpf_map_delete_elem mock_delete
#define bpf_ringbuf_reserve mock_reserve
#define bpf_ringbuf_submit mock_submit
#include "../cap_audit.bpf.c"

#define TASKS 32
static __u8 phases[TASKS];
static struct syscall_state syscalls[TASKS];
static struct cap_event inflight[TASKS];
static bool syscall_present[TASKS], inflight_present[TASKS];
static struct cap_event output;
static unsigned int submitted;

static void check(bool condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(EXIT_FAILURE);
	}
}

static unsigned int task_index(const void *map, const void *key)
{
	unsigned int tid = map == &target_pids ?
		*(__u32 *)key : (__u32)*(__u64 *)key;

	check(tid < TASKS, "Unexpected test task ID");
	return tid;
}

static void *mock_lookup(const void *map, const void *key)
{
	unsigned int tid = task_index(map, key);

	if (map == &target_pids)
		return phases[tid] ? &phases[tid] : NULL;
	if (map == &current_syscalls)
		return syscall_present[tid] ? &syscalls[tid] : NULL;
	check(map == &cap_events_inflight, "Unexpected map lookup");
	return inflight_present[tid] ? &inflight[tid] : NULL;
}

static long mock_update(const void *map, const void *key,
			const void *value, __u64 flags)
{
	unsigned int tid = task_index(map, key);

	(void)flags;
	if (map == &target_pids)
		phases[tid] = *(__u8 *)value;
	else if (map == &current_syscalls) {
		syscalls[tid] = *(const struct syscall_state *)value;
		syscall_present[tid] = true;
	} else {
		check(map == &cap_events_inflight, "Unexpected map update");
		inflight[tid] = *(const struct cap_event *)value;
		inflight_present[tid] = true;
	}
	return 0;
}

static long mock_delete(const void *map, const void *key)
{
	unsigned int tid = task_index(map, key);

	if (map == &target_pids)
		phases[tid] = 0;
	else if (map == &current_syscalls)
		syscall_present[tid] = false;
	else {
		check(map == &cap_events_inflight, "Unexpected map deletion");
		inflight_present[tid] = false;
	}
	return 0;
}

static void *mock_reserve(const void *map, __u64 size, __u64 flags)
{
	(void)flags;
	check(map == &cap_events && size == sizeof(output),
	      "Unexpected ring buffer reservation");
	return &output;
}

static void mock_submit(void *data, __u64 flags)
{
	(void)flags;
	check(data == &output, "Unexpected ring buffer submission");
	submitted++;
}

static void test_namespace(__u32 inum)
{
	struct user_namespace ns = { .ns.inum = inum };
	struct cred cred = { .user_ns = &ns };
	struct pt_regs regs = { .orig_ax = 123 };
	unsigned int before = submitted;

	current_task = ((__u64)10 << 32) | 10;
	phases[10] = 2;
	trace_cap_capable(&regs, &cred, &ns, 21, 0);
	trace_cap_capable_ret(&regs, 0);
	check(submitted == before + 1, "Capability event was not emitted");
	check(output.targ_ns_inum == inum, "Wrong target namespace inode");
	check(output.pid == 10 && output.tid == 10 && output.result == 1,
	      "Capability event lost task identity or result");
}

int main(void)
{
	test_namespace(100);
	test_namespace(200);
	puts("cap-audit BPF event tests passed");
	return 0;
}
