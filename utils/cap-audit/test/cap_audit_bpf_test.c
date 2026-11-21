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
	kernel_cap_t cap_inheritable, cap_permitted, cap_effective;
};
struct task_struct { const struct cred *cred; };
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
static long mock_probe_read_kernel(void *dst, __u32 size, const void *src);
static __u64 current_task;
static struct task_struct mock_task;
static bool fail_kernel_read;

/* Keep the production functions; replace only kernel helper boundaries. */
#undef BPF_KPROBE
#undef BPF_KRETPROBE
#undef BPF_CORE_READ
#undef bpf_core_read
#undef bpf_core_type_size
#undef bpf_core_type_exists
#define BPF_KPROBE(name, ...) name(struct pt_regs *ctx, __VA_ARGS__)
#define BPF_KRETPROBE(name, ...) name(struct pt_regs *ctx, __VA_ARGS__)
#define BPF_CORE_READ(src, field) ((src)->field)
#define bpf_core_read(dst, size, src) \
	mock_probe_read_kernel(dst, size, src)
#define bpf_core_type_size(type) sizeof(type)
#define bpf_core_type_exists(type) 0
#define bpf_probe_read_kernel mock_probe_read_kernel
#define bpf_get_current_task() ((__u64)&mock_task)
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

/* Copy kernel memory unless the test is exercising a read failure. */
static long mock_probe_read_kernel(void *dst, __u32 size, const void *src)
{
	if (fail_kernel_read)
		return -1;
	memcpy(dst, src, size);
	return 0;
}

/* Cover both kernel_cap_t layouts on little- and big-endian targets. */
static void test_cap_mask_layouts(void)
{
	const __u32 legacy_words[2] = { 0x89abcdefU, 0x01234567U };
	const __u32 u64_big_endian_words[2] = { 0x01234567U, 0x89abcdefU };
	const __u64 expected = 0x0123456789abcdefULL;

	check(cap_words_to_mask(legacy_words, 1, 0) == expected,
	      "Little-endian legacy capability layout was decoded incorrectly");
	check(cap_words_to_mask(legacy_words, 0, 0) == expected,
	      "Little-endian u64 capability layout was decoded incorrectly");
	check(cap_words_to_mask(legacy_words, 1, 1) == expected,
	      "Big-endian legacy capability layout was decoded incorrectly");
	check(cap_words_to_mask(u64_big_endian_words, 0, 1) == expected,
	      "Big-endian u64 capability layout was decoded incorrectly");
}

/* Model the kernel hook reached only by a real native capset invocation. */
static void mark_native_capset(struct cred *cred)
{
	struct pt_regs regs = { 0 };

	trace_cap_capset(&regs, cred, cred, &cred->cap_effective,
			 &cred->cap_inheritable);
	trace_cap_capset_ret(&regs, 0);
}

/* Prove the kernel hook authenticates capset and evidence uses committed data. */
static void test_capset_evidence(void)
{
	struct {
		__u32 version;
		int pid;
	} user_header = { .version = 0x20080522, .pid = 0 };
	/* The permitted word advertises CAP_SYS_ADMIN to the entry probe. */
	__u32 user_data[6] = { 0, 1U << 21, 0, 0, 0, 0 };
	struct trace_event_raw_sys_enter enter = {
		.id = capset_syscall_nr,
		.args = {
			(unsigned long)&user_header,
			(unsigned long)user_data,
		},
	};
	struct trace_event_raw_sys_exit exit = { .ret = 0 };
	struct cred installed = { 0 };
	unsigned int before;

	current_task = ((__u64)25 << 32) | 25;
	phases[25] = 2;
	mock_task.cred = &installed;

	/* A compat-ABI syscall can have the same raw number as native capset.
	 * Without the cap_capset kernel hook it must establish no evidence,
	 * even when the thread already holds capabilities.
	 */
	installed.cap_effective.val = (1ULL << 41) - 1;
	installed.cap_permitted.val = (1ULL << 41) - 1;
	before = submitted;
	trace_sys_enter(&enter);
	trace_sys_exit(&exit);
	check(submitted == before,
	      "Syscall-number collision emitted capset evidence");

	/* Model a sibling clearing the forged entry payload before the kernel
	 * copies it. A genuine successful capset reports the committed zero set.
	 */
	installed.cap_effective.val = 0;
	installed.cap_permitted.val = 0;
	trace_sys_enter(&enter);
	user_data[1] = 0;
	mark_native_capset(&installed);
	trace_sys_exit(&exit);
	check(submitted == before + 1 &&
	      output.event_type == CAP_EVENT_CAPSET,
	      "Successful capset event was not emitted");
	check(output.capset_effective == 0 && output.capset_permitted == 0 &&
	      output.capset_inheritable == 0,
	      "Capset event used the mutable userspace snapshot");

	/* Optional SETPCAP analysis may fail without hiding a real capset. */
	before = submitted;
	trace_sys_enter(&enter);
	fail_kernel_read = true;
	mark_native_capset(&installed);
	fail_kernel_read = false;
	trace_sys_exit(&exit);
	check(submitted == before + 1 &&
	      output.event_type == CAP_EVENT_CAPSET,
	      "Optional probe read failure hid a successful capset");

	/* Kernel-installed low and high capability bits remain observable. */
	installed.cap_effective.val = 1ULL << 5;
	installed.cap_permitted.val = (1ULL << 5) | (1ULL << 40);
	installed.cap_inheritable.val = 1ULL << 40;
	before = submitted;
	trace_sys_enter(&enter);
	mark_native_capset(&installed);
	trace_sys_exit(&exit);
	check(submitted == before + 1 &&
	      output.capset_effective == installed.cap_effective.val &&
	      output.capset_permitted == installed.cap_permitted.val &&
	      output.capset_inheritable == installed.cap_inheritable.val,
	      "Capset event lost installed capability bits");

	/* Failed calls and unsafe kernel reads establish no recommendation. */
	before = submitted;
	exit.ret = -1;
	trace_sys_enter(&enter);
	mark_native_capset(&installed);
	trace_sys_exit(&exit);
	check(submitted == before, "Failed capset emitted installed masks");
	exit.ret = 0;
	trace_sys_enter(&enter);
	mark_native_capset(&installed);
	fail_kernel_read = true;
	trace_sys_exit(&exit);
	fail_kernel_read = false;
	check(submitted == before, "Unreadable credentials emitted capset masks");

	/* Service setup before the exec phase remains outside target evidence. */
	phases[25] = 1;
	trace_sys_enter(&enter);
	mark_native_capset(&installed);
	trace_sys_exit(&exit);
	check(submitted == before, "Pre-exec capset was recorded");
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

static void test_thread_lifecycle(void)
{
	struct trace_event_raw_sched_process_fork fork_event = {
		.parent_pid = 10, .child_pid = 11,
	};
	struct trace_event_raw_sched_process_template exit_event = { .pid = 10 };
	struct trace_event_raw_sched_process_exec exec_event = {
		.pid = 10, .old_pid = 11,
	};
	struct trace_event_raw_sys_enter syscall = { .id = 123 };
	struct pt_regs regs = { 0 };
	unsigned int before;

	memset(phases, 0, sizeof(phases));
	memset(syscall_present, 0, sizeof(syscall_present));
	phases[10] = 2;
	current_task = ((__u64)10 << 32) | 10;
	trace_sched_process_fork(&fork_event);
	check(phases[11] == 2, "New thread did not inherit tracing");

	/* A leader can exit through pthread_exit while its worker runs on. */
	trace_sys_enter(&syscall);
	trace_sched_process_exit(&exit_event);
	current_task = ((__u64)10 << 32) | 11;
	before = submitted;
	trace_sys_enter(&syscall);
	trace_cap_capable(&regs, NULL, NULL, 21, 0);
	trace_cap_capable_ret(&regs, 0);
	check(submitted == before + 1 && output.tid == 11,
	      "Leader exit stopped capability tracing for a live worker");
	check(!syscall_present[10], "Exiting task leaked syscall state");
	check(output.syscall_nr == 123, "Worker lost syscall attribution");

	/* Forks from the surviving worker must remain in the target tree. */
	fork_event.parent_pid = 11;
	fork_event.child_pid = 12;
	trace_sched_process_fork(&fork_event);
	check(phases[12] == 2, "Worker's child lost tracing");

	/* Non-leader exec adopts the leader's TID before sched_process_exec. */
	current_task = ((__u64)10 << 32) | 10;
	trace_sched_process_exec(&exec_event);
	check(phases[10] == 2 && phases[11] == 0,
	      "Non-leader exec lost tracing or retained its old TID");
	check(syscall_present[10] && !syscall_present[11] &&
	      syscalls[10].nr == 123, "Exec did not move syscall attribution");
	check(output.event_type == CAP_EVENT_TASK_END && output.tid == 11,
	      "Exec did not close the old thread's keepcaps window");
	before = submitted;
	trace_cap_capable(&regs, NULL, NULL, 21, 0);
	trace_cap_capable_ret(&regs, 0);
	check(submitted == before + 1 && output.tid == 10,
	      "Non-leader exec stopped capability tracing");
	trace_sched_process_exit(&exit_event);
	check(!phases[10] && !syscall_present[10] && !inflight_present[10],
	      "Exited thread retained BPF state");
	check(phases[12] == 2, "Exiting parent stopped its child's tracing");
}

static void test_exec_gate(void)
{
	struct trace_event_raw_sched_process_fork fork_event = {
		.parent_pid = 20, .child_pid = 21,
	};
	struct trace_event_raw_sched_process_exec exec_event = {
		.pid = 21, .old_pid = 21,
	};
	struct trace_event_raw_sched_process_template exit_event = { .pid = 22 };
	struct pt_regs regs = { 0 };
	unsigned int before = submitted;

	phases[20] = 1;
	current_task = ((__u64)20 << 32) | 20;
	trace_sched_process_fork(&fork_event);
	check(phases[21] == 1, "Pre-exec child lost its phase");
	current_task = ((__u64)21 << 32) | 21;
	trace_cap_capable(&regs, NULL, NULL, 21, 0);
	trace_cap_capable_ret(&regs, 0);
	check(submitted == before, "Pre-exec capability noise was recorded");
	trace_sched_process_exec(&exec_event);
	trace_cap_capable(&regs, NULL, NULL, 21, 0);
	trace_cap_capable_ret(&regs, 0);
	check(submitted == before + 1, "Initial exec did not open the phase gate");

	fork_event.parent_pid = 21;
	fork_event.child_pid = 22;
	trace_sched_process_fork(&fork_event);
	current_task = ((__u64)21 << 32) | 22;
	trace_sched_process_exit(&exit_event);
	check(!phases[22] && phases[21] == 2,
	      "Worker exit removed its live leader from tracing");
}

static void test_exit_identity(void)
{
	struct trace_event_raw_sched_process_template unrelated = { .pid = 23 };
	struct trace_event_raw_sys_enter syscall = { .id = 123 };

	/* Exit's layout can differ from sched_process_template. Bytes at the
	 * template's pid offset must not select an unrelated task for removal.
	 */
	phases[23] = phases[24] = 2;
	current_task = ((__u64)24 << 32) | 24;
	trace_sys_enter(&syscall);
	trace_sched_process_exit(&unrelated);
	check(phases[23] == 2 && !phases[24] && !syscall_present[24],
	      "Exit cleanup used a mismatched tracepoint layout");
	check(output.event_type == CAP_EVENT_TASK_END && output.tid == 24,
	      "Exit event identified the wrong thread");
}

int main(void)
{
	test_namespace(100);
	test_namespace(200);
	test_cap_mask_layouts();
	test_capset_evidence();
	test_thread_lifecycle();
	test_exec_gate();
	test_exit_identity();
	puts("cap-audit BPF event tests passed");
	return 0;
}
