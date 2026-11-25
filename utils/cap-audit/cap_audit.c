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

#include "cap_audit.h"
#include "cap_audit_path.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libaudit.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Overview:
 * cap-audit launches a target application, traces that process tree using
 * eBPF hooks, and reports which Linux capabilities were actually exercised.
 * The userspace side performs three major jobs:
 *
 * (1) prepare the runtime environment by checking our own capabilities and
 * raising rlimits;
 * (2) coordinate with the eBPF program by registering the target PID before
 * exec() and consuming capability check events from the ring buffer; and
 * (3) analyze collected data to present required, conditional, and denied
 * capabilities in human and machine-readable formats.
 *
 * When the tool observes a capset syscall from the initial PID, it splits
 * capability accounting into initialization and operational phases. The
 * initialization phase covers all capability checks from process start to
 * the first capset, plus UID/GID changes bracketed by successful keepcaps
 * enable/disable calls on the same thread. The operational phase covers
 * other checks after the first capset. This distinguishes capabilities needed
 * for one-time setup (binding ports, chroot, loading restricted configuration)
 * from capabilities needed for ongoing operation. Recommendations for
 * programmatic capability dropping use only the operational set, while
 * deployment recommendations (file capabilities, systemd, containers) use
 * the union since the process must start with sufficient capabilities for
 * initialization. Programs that never call capset produce an undifferentiated
 * report identical to previous versions.
 *
 * Core design problem:
 * when tracing as root, many capability checks come from kernel-internal
 * work under the same PID rather than from app logic. The tool uses a
 * two-layer noise filter pipeline, split between BPF and userspace, to
 * separate real requirements from incidental checks.
 *
 * Layer 1 - pre-exec noise (BPF phase gate):
 * after fork() but before execve() completes, the child is still this
 * auditor image. PATH lookup, directory traversal, and exec machinery can
 * trigger checks like DAC_READ_SEARCH/SYS_ADMIN/SETPCAP that are unrelated
 * to the target app. The BPF side tracks PID phases and suppresses all
 * capability events until sched_process_exec transitions the PID from
 * phase 1 (pre-exec) to phase 2 (post-exec).
 *
 * Layer 2 - userspace always-noise filter:
 * handle_cap_event() unconditionally drops two classes of capability
 * checks that never represent real application requirements. First,
 * execve-triggered SYS_ADMIN and SETPCAP checks are kernel-internal
 * credential-transition noise. Second, cap-audit identifies the known
 * advisory memory overcommit probe by combining syscall, capability, and
 * CAP_OPT_NOAUDIT: cap_vm_enough_memory checks CAP_SYS_ADMIN on
 * brk/mmap/mprotect/mremap and the operation succeeds regardless of the
 * result. CAP_OPT_NOAUDIT means "do not audit", not "advisory", so it
 * is only a confirming signal here. Other enforcement checks also use
 * CAP_OPT_NOAUDIT to avoid audit spam, and must still be reported. The
 * syscall + capability match identifies the specific advisory call site,
 * while CAP_OPT_NOAUDIT confirms that the event followed the advisory path
 * rather than a security-gating path on the same syscall.
 *
 * PID filtering remains central: parent registers the child immediately after
 * fork(), BPF follows forks/exits to keep the target set precise, and each
 * event carries capability, syscall context, namespace info, and result for
 * per-capability aggregation.
 *
 * Parent/child startup is synchronized with a pipe. The child blocks in
 * read(sync_pipe) until the parent has inserted its PID in target_pids and
 * written a go byte. That ordering prevents missed events and prevents events
 * from arriving before the PID is registered.
 */

struct audit_state state;
int audit_machine = -1;

static char **prepend_execstart_argv(const service_config_t *cfg,
				     char **args, int arg_count)
	__attribute_malloc__
	__attr_dealloc_free
	__attr_access ((__read_only__, 1))
	__attr_access ((__read_only__, 2))
	__wur;
static int has_service_suffix(const char *path)
	__attr_access ((__read_only__, 1))
	__attribute_pure__;

static int read_user_ns_inum(__u32 *inum)
{
	struct stat st;

	if (stat("/proc/self/ns/user", &st) != 0) {
		fprintf(stderr, "Error: failed to read user namespace: %s\n",
			strerror(errno));
		return -1;
	}
	if (st.st_ino == 0 || st.st_ino > UINT_MAX) {
		fprintf(stderr, "Error: invalid user namespace inode\n");
		return -1;
	}

	*inum = (__u32)st.st_ino;
	return 0;
}

static void sig_handler(int sig __attribute__((unused)))
{
	state.stop = sig;
}

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

static int init_capng(void)
{
	capng_clear(CAPNG_SELECT_BOTH);

	if (capng_get_caps_process() != 0) {
		fprintf(stderr, "Error: Failed to get process capabilities\n");
		return -1;
	}

	return 0;
}

static char **prepend_execstart_argv(const service_config_t *cfg,
				     char **args, int arg_count)
{
	char **argv;
	int i;

	argv = calloc((size_t)arg_count + 2, sizeof(char *));
	if (!argv)
		return NULL;

	argv[0] = cfg->exec_argv[0];
	for (i = 0; i < arg_count; i++)
		argv[i + 1] = args[i];
	argv[arg_count + 1] = NULL;

	return argv;
}

static int has_service_suffix(const char *path)
{
	size_t len;
	const char suffix[] = ".service";
	size_t suffix_len = sizeof(suffix) - 1;

	if (!path)
		return 0;

	len = strlen(path);
	return len >= suffix_len &&
	       strcmp(path + len - suffix_len, suffix) == 0;
}

static int check_auditor_caps(void)
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

	return 0;
}

static int set_target_pid(pid_t pid)
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
		fprintf(stderr, "[*] Registered PID %d for tracing\n", pid);

	return 0;
}

static void usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s [options] -- command [args...]\n", prog);
	fprintf(out, "       %s --service FILE [-- command-or-args...]\n", prog);
	fprintf(out, "Options:\n");
	fprintf(out, "  -h, --help          Show this help message\n");
	fprintf(out, "  -v, --verbose       Verbose output\n");
	fprintf(out, "  -j, --json          JSON output\n");
	fprintf(out, "  -y, --yaml          YAML output\n");
	fprintf(out, "  -s, --service FILE  Simulate a systemd service unit\n");
	fprintf(out, "      --follow-descendants\n"
		"                      Keep tracing until every descendant exits\n");
}

#ifndef CAP_AUDIT_NO_MAIN
int main(int argc, char **argv)
{
	int err;
	int arg_idx;
	pid_t child;
	pid_t ret_pid;
	int wstatus;
	char *target_path = NULL;
	char **service_target_argv = NULL;
	int separator_seen = 0;
	int exec_pipe[2];
	ssize_t exec_bytes;

	if (argc < 2) {
		usage(stderr, argv[0]);
		return 1;
	}

	arg_idx = 1;
	while (arg_idx < argc && argv[arg_idx][0] == '-') {
		if (!strcmp(argv[arg_idx], "-h") ||
		    !strcmp(argv[arg_idx], "--help")) {
			usage(stdout, argv[0]);
			return 0;
		} else if (!strcmp(argv[arg_idx], "-v") ||
			   !strcmp(argv[arg_idx], "--verbose"))
			state.verbose = 1;
		else if (!strcmp(argv[arg_idx], "-j") ||
			 !strcmp(argv[arg_idx], "--json"))
			state.json_output = 1;
		else if (!strcmp(argv[arg_idx], "-y") ||
			 !strcmp(argv[arg_idx], "--yaml"))
			state.yaml_output = 1;
		else if (!strcmp(argv[arg_idx], "--follow-descendants"))
			state.observation.descendants_followed = true;
		else if (!strcmp(argv[arg_idx], "-s") ||
			 !strcmp(argv[arg_idx], "--service")) {
			char *service_file;

			arg_idx++;
			if (arg_idx >= argc) {
				fprintf(stderr,
					"Error: --service requires a file\n");
				usage(stderr, argv[0]);
				return 1;
			}
			service_file = strdup(argv[arg_idx]);
			if (!service_file)
				return 1;
			free(state.service_file);
			state.service_file = service_file;
		}
		else if (!strcmp(argv[arg_idx], "--")) {
			separator_seen = 1;
			arg_idx++;
			break;
		} else {
			fprintf(stderr, "Error: Unknown option '%s'\n",
				argv[arg_idx]);
			usage(stderr, argv[0]);
			return 1;
		}
		arg_idx++;
	}

	if (state.service_file) {
		state.service_cfg = calloc(1, sizeof(*state.service_cfg));
		if (!state.service_cfg)
			goto err_target_path;

		if (parse_service_file(state.service_file,
				       state.service_cfg) != 0)
			goto err_target_path;

		if (!separator_seen && arg_idx < argc) {
			fprintf(stderr,
				"Error: --service command overrides require --\n");
			usage(stderr, argv[0]);
			goto err_target_path;
		}

		/*
		 * Check ExecStart expansions only after choosing what will run.
		 * Words replaced by an explicit override are never executed, and
		 * an override is the documented way to audit a unit whose command
		 * needs expansions cap-audit cannot reproduce. The unit's user,
		 * group, capability and prefix settings still apply either way.
		 */
		if (separator_seen && arg_idx < argc) {
			if (argv[arg_idx][0] == '-') {
				if (!state.service_cfg->exec_argv) {
					fprintf(stderr,
						"Error: service has no ExecStart executable for argument override\n");
					goto err_target_path;
				}
				/* Only the unit's executable is kept. */
				if (resolve_service_command(state.service_cfg,
							    1) != 0)
					goto err_target_path;
				service_target_argv =
				    prepend_execstart_argv(state.service_cfg,
							   &argv[arg_idx],
							   argc - arg_idx);
				if (!service_target_argv)
					goto err_target_path;
				state.target_argv = service_target_argv;
			} else {
				state.target_argv = &argv[arg_idx];
			}
		} else {
			if (!state.service_cfg->exec_argv) {
				fprintf(stderr,
					"Error: service has no ExecStart command\n");
				goto err_target_path;
			}
			if (resolve_service_command(state.service_cfg,
				    state.service_cfg->exec_argc) != 0)
				goto err_target_path;
			state.target_argv = state.service_cfg->exec_argv;
		}
	} else if (arg_idx >= argc) {
		fprintf(stderr, "Error: No command specified\n");
		usage(stderr, argv[0]);
		return 1;
	} else {
		state.target_argv = &argv[arg_idx];
	}

	/*
	 * Fail before capability checks, BPF setup, or fork/exec tracing so
	 * a bad target command is reported directly by cap-audit.
	 */
	target_path = resolve_target_command(state.target_argv[0]);
	if (!target_path) {
		fprintf(stderr, "Error: target is not executable: %s\n",
			state.target_argv[0]);
		if (!state.service_file &&
		    has_service_suffix(state.target_argv[0]))
			fprintf(stderr,
				"Hint: to audit a systemd unit, use --service FILE\n");
		goto err_target_path;
	}
	if (read_user_ns_inum(&state.baseline_user_ns_inum) != 0)
		goto err_target_path;

	if (init_capng() != 0)
		goto err_target_path;

	if (check_auditor_caps() != 0)
		goto err_target_path;

	if (set_memlock_rlimit() != 0)
		goto err_target_path;

	state.app.exe = strdup(state.target_argv[0]);
	state.app.prog_type = UNSUPPORTED;
	if (audit_machine < 0)
		audit_machine = audit_detect_machine();
	if (audit_machine < 0) {
		fprintf(stderr,
			"Error: unable to determine hardware architecture for syscall lookup. Exiting.\n");
		free(state.app.exe);
		goto err_target_path;
	}
	state.app.execve_nr = audit_name_to_syscall("execve", audit_machine);
	state.app.mmap_nr = audit_name_to_syscall("mmap", audit_machine);
	state.app.brk_nr = audit_name_to_syscall("brk", audit_machine);
	state.app.mprotect_nr = audit_name_to_syscall("mprotect",
						      audit_machine);
	state.app.mremap_nr = audit_name_to_syscall("mremap", audit_machine);
	state.skel = cap_audit_bpf__open();
	if (!state.skel) {
		fprintf(stderr, "Error: Failed to open BPF program: %s\n",
			strerror(errno));
		free(state.app.exe);
		goto err_target_path;
	}
	state.skel->rodata->prctl_syscall_nr =
		audit_name_to_syscall("prctl", audit_machine);
	err = cap_audit_bpf__load(state.skel);
	if (err) {
		fprintf(stderr, "Error: Failed to load BPF program: %s\n",
			strerror(-err));
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	err = cap_audit_bpf__attach(state.skel);
	if (err) {
		fprintf(stderr, "Error: Failed to attach BPF programs: %s\n",
			strerror(-err));
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	state.rb = ring_buffer__new(bpf_map__fd(state.skel->maps.cap_events),
				    handle_cap_event, NULL, NULL);
	if (!state.rb) {
		fprintf(stderr, "Error: Failed to create ring buffer: %s\n",
			strerror(errno));
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	fprintf(stderr, "[*] Capability auditor started\n");

	if (pipe(state.sync_pipe) != 0) {
		fprintf(stderr, "Error: pipe failed: %s\n", strerror(errno));
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}
	/* EOF follows successful exec, while a child-side setup failure sends
	 * errno. This distinguishes launch failure from the target's own exit.
	 */
	if (pipe2(exec_pipe, O_CLOEXEC) != 0) {
		close(state.sync_pipe[0]);
		close(state.sync_pipe[1]);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	/*
	 * Following descendants requires that they stay waitable after their
	 * parents exit. As a child subreaper, cap-audit adopts orphaned
	 * descendants of the target, such as a daemon that forks and exits,
	 * instead of init, so it can tell when the last one has exited.
	 */
	if (state.observation.descendants_followed &&
	    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
		fprintf(stderr, "Error: cannot follow descendants: %s\n",
			strerror(errno));
		close(state.sync_pipe[0]);
		close(state.sync_pipe[1]);
		close(exec_pipe[0]);
		close(exec_pipe[1]);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	child = fork();
	if (child == 0) {
		char sync_byte;
		ssize_t bytes;

		close(exec_pipe[0]);
		close(state.sync_pipe[1]);
		/* Machine reports own stdout. The executed workload receives
		 * stderr for its ordinary output and no copy of that report fd.
		 */
		if ((state.json_output || state.yaml_output) &&
		    dup2(STDERR_FILENO, STDOUT_FILENO) < 0)
			goto child_launch_failed;
		bytes = read(state.sync_pipe[0], &sync_byte, 1);
		if (bytes != 1) {
			/*
			 * EOF leaves errno untouched, so it may still hold a
			 * value from earlier setup such as the PATH lookup.
			 * Capture the cause before stdio or close() can
			 * overwrite it, and report EOF as an I/O error.
			 */
			int error = bytes < 0 ? errno : EIO;

			if (bytes < 0)
				perror("read");
			else
				fprintf(stderr,
					"Error: failed to sync with parent\n");
			close(state.sync_pipe[0]);
			errno = error;
			goto child_launch_failed;
		}
		close(state.sync_pipe[0]);
		if (state.service_cfg &&
		    apply_service_config(state.service_cfg) != 0) {
			errno = EINVAL;
			goto child_launch_failed;
		}
		/*
		 * The earlier path check is only diagnostic. Repeat lookup here
		 * so execvp() preserves PATH fallback if a candidate changes.
		 */
		execvp(state.target_argv[0], state.target_argv);
child_launch_failed:
		{
			int error = errno ? errno : EIO;

			fprintf(stderr, "Error: target launch failed: %s\n",
				strerror(error));
			/* An int is below PIPE_BUF and cannot be partially sent. */
			while (write(exec_pipe[1], &error, sizeof(error)) < 0 &&
			       errno == EINTR)
				;
			_exit(1);
		}
	} else if (child < 0) {
		fprintf(stderr, "Error: fork failed: %s\n", strerror(errno));
		close(state.sync_pipe[0]);
		close(state.sync_pipe[1]);
		close(exec_pipe[0]);
		close(exec_pipe[1]);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	state.app.pid = child;
	state.skel->bss->initial_target_tid = child;
	close(exec_pipe[1]);

	close(state.sync_pipe[0]);
	if (set_target_pid(child) != 0) {
		close(state.sync_pipe[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(exec_pipe[0]);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}

	if (write(state.sync_pipe[1], "1", 1) != 1) {
		fprintf(stderr, "Error: write failed: %s\n", strerror(errno));
		close(state.sync_pipe[1]);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(exec_pipe[0]);
		ring_buffer__free(state.rb);
		cap_audit_bpf__destroy(state.skel);
		free(state.app.exe);
		goto err_target_path;
	}
	close(state.sync_pipe[1]);
	do {
		exec_bytes = read(exec_pipe[0], &state.observation.launch_error,
				  sizeof(state.observation.launch_error));
	} while (exec_bytes < 0 && errno == EINTR && !state.stop);
	close(exec_pipe[0]);
	if (exec_bytes != 0 && exec_bytes != sizeof(int))
		state.observation.launch_error = EIO;

	{
		char resolved[PATH_MAX];

		if (resolve_target_exe(child, resolved, sizeof(resolved)) == 0) {
			char *resolved_dup = strdup(resolved);

			if (resolved_dup) {
				free(state.app.exe);
				state.app.exe = resolved_dup;
			}
			state.app.prog_type = classify_app(state.app.exe);
		} else {
			fprintf(stderr,
				"Warning: unable to resolve target path\n");
		}
	}

	read_system_state(&state.app);
	if (state.app.prog_type == PYTHON && state.verbose)
		fprintf(stderr, "[*] Script interpreter: %s\n", state.app.exe);
	if (state.service_cfg && state.verbose)
		print_service_config(state.service_cfg);
	fprintf(stderr, "[*] Tracing application: %s (PID %d)\n", state.app.exe, child);
	fprintf(stderr, "[*] Press Ctrl-C to stop\n\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!state.stop) {
		err = ring_buffer__poll(state.rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer: %s\n",
				strerror(-err));
			state.observation.stop_reason = TRACE_STOP_POLL_ERROR;
			break;
		}

		/*
		 * When following descendants, reap every adopted child too and
		 * stop only when none remain. The initial target's status is
		 * still the one reported.
		 */
		while ((ret_pid = waitpid(state.observation.descendants_followed ?
					  -1 : child, &wstatus, WNOHANG)) > 0) {
			if (ret_pid != child)
				continue;
			state.observation.target_exited = true;
			state.observation.wait_status = wstatus;
			if (WIFEXITED(wstatus))
				fprintf(stderr,
				   "\n[*] Application exited with status %d\n",
				   WEXITSTATUS(wstatus));
			else if (WIFSIGNALED(wstatus))
				fprintf(stderr,
				  "\n[*] Application terminated by signal %d\n",
				  WTERMSIG(wstatus));
			if (!state.observation.descendants_followed)
				break;
			fprintf(stderr, "[*] Following descendants until they "
				"exit\n");
		}
		if (state.observation.target_exited &&
		    (!state.observation.descendants_followed ||
		     (ret_pid < 0 && errno == ECHILD))) {
			state.observation.stop_reason = TRACE_STOP_TARGET_EXIT;
			break;
		}
		if (ret_pid < 0 && errno != EINTR) {
			state.observation.stop_reason = TRACE_STOP_WAIT_ERROR;
			break;
		}
	}
	if (state.stop)
		state.observation.stop_reason = TRACE_STOP_REQUESTED;

	fprintf(stderr, "[*] Analyzing results...\n");

	/*
	 * The normal exec/memory filters also cover interpreter teardown.
	 * Drain time says nothing about when a queued check occurred, so do
	 * not discard SYS_ADMIN/SETPCAP merely because the target has exited.
	 */
	/* Freeze producers before draining and reading loss counters. Tasks
	 * left in the target map identify descendants outside this trace.
	 */
	cap_audit_bpf__detach(state.skel);
	if (ring_buffer__consume(state.rb) < 0)
		state.observation.stop_reason = TRACE_STOP_POLL_ERROR;
	{
		__u32 key;
		int fd = bpf_map__fd(state.skel->maps.target_pids);

		if (bpf_map_get_next_key(fd, NULL, &key) == 0)
			state.observation.descendants_remaining = true;
		else if (errno != ENOENT)
			state.observation.map_failures++;
	}
	state.observation.exec_confirmed = state.skel->bss->initial_exec_seen;
	state.observation.map_failures += state.skel->bss->lost_map_updates;
	state.observation.ring_failures = state.skel->bss->lost_ring_events;
	state.observation.capset_read_failures = state.skel->bss->lost_capset_reads;
	finish_cap_events();

	if (state.json_output)
		output_json();
	else if (state.yaml_output)
		output_yaml();
	else
		analyze_capabilities();

	ring_buffer__free(state.rb);
	cap_audit_bpf__destroy(state.skel);
	free(state.app.exe);
	free(target_path);
	free(service_target_argv);
	if (state.service_cfg) {
		free_config(state.service_cfg);
		free(state.service_cfg);
	}
	free(state.service_file);
	free_cap_checks();

	/* A workload's nonzero exit remains diagnostic. Collection and launch
	 * failures make this observation incomplete regardless of that exit.
	 */
	return audit_collection_reason() ? 2 : 0;

err_target_path:
	free(target_path);
	free(service_target_argv);
	if (state.service_cfg) {
		free_config(state.service_cfg);
		free(state.service_cfg);
	}
	free(state.service_file);
	return 1;
}
#endif
