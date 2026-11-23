// SPDX-License-Identifier: GPL-2.0-or-later
/* Live production BPF events compared with independent capget observations. */
#include "cap_audit.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct masks { uint64_t e, p, i; };
static int emit_expected = 1;
static int expected_nr = SYS_capset;
static const char *trace_case;
static pthread_t leader;
static atomic_int stop_race;
static struct __user_cap_data_struct raced[2];

static void die(const char *s)
{
	perror(s);
	exit(1);
}

static void unavailable(const char *operation)
{
	int error = errno;

	fprintf(stderr, "UNAVAILABLE: %s: %s (%d)\n", operation,
		strerror(error), error);
	exit(77);
}

static void procfs_failure(const char *operation)
{
	/* Missing or denied metadata prevents an independent observation.
	 * Other failures, such as EIO, must not silently become coverage skips.
	 */
	if (errno == ENOENT || errno == ENOTDIR || errno == ENOSYS ||
	    errno == EACCES || errno == EPERM)
		unavailable(operation);
	die(operation);
}

static void record(const char *tag, unsigned int tid, unsigned int pid,
		   struct masks m)
{
	char line[256];
	int n = snprintf(line, sizeof(line), "%s %u %u %016llx %016llx %016llx\n",
			 tag, tid, pid, (unsigned long long)m.e,
			 (unsigned long long)m.p, (unsigned long long)m.i);
	if (write(STDOUT_FILENO, line, n) != n)
		die("write record");
}

static struct masks get_masks(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2] = { 0 };
	struct masks m;

	if (syscall(SYS_capget, &h, d))
		die("capget");
	m.e = d[0].effective | ((uint64_t)d[1].effective << 32);
	m.p = d[0].permitted | ((uint64_t)d[1].permitted << 32);
	m.i = d[0].inheritable | ((uint64_t)d[1].inheritable << 32);
	return m;
}

static int equal(struct masks a, struct masks b)
{
	return a.e == b.e && a.p == b.p && a.i == b.i;
}

static void pack(struct __user_cap_data_struct d[2], struct masks m)
{
	d[0] = (struct __user_cap_data_struct) { m.e, m.p, m.i };
	d[1] = (struct __user_cap_data_struct) { m.e >> 32, m.p >> 32, m.i >> 32 };
}

/* capget is independent of the BPF reader and runs in the calling thread.
 * No signal handler or second capset changes this thread between the calls.
 */
static void observed_success(void)
{
	if (emit_expected)
		record("EXP", syscall(SYS_gettid), getpid(), get_masks());
}

static void install(struct masks m, unsigned int version)
{
	struct __user_cap_header_struct h = { version, 0 };
	struct __user_cap_data_struct d[2];
	struct masks expected = m;

	pack(d, m);
	if (syscall(SYS_capset, &h, d))
		die("capset");
	if (version == _LINUX_CAPABILITY_VERSION_1) {
		expected.e &= UINT32_MAX;
		expected.p &= UINT32_MAX;
		expected.i &= UINT32_MAX;
	}
	if (!equal(expected, get_masks())) {
		fprintf(stderr, "Kernel masks differ from deterministic request\n");
		exit(1);
	}
	observed_success();
}

static void rejected(struct __user_cap_header_struct *h,
		     struct __user_cap_data_struct *d, int error)
{
	struct masks before = get_masks();

	errno = 0;
	if (syscall(SYS_capset, h, d) != -1 || errno != error ||
	    !equal(before, get_masks())) {
		fprintf(stderr, "Failed capset had unexpected errno "
			"or changed credentials\n");
		exit(1);
	}
}

static uint64_t first_bit(uint64_t mask)
{
	return mask & (~mask + 1);
}

static struct masks mixed_masks(void)
{
	struct masks base = get_masks(), m;
	uint64_t low = base.p & UINT32_MAX;
	uint64_t high = first_bit(base.p & ~((uint64_t)UINT32_MAX));
	uint64_t a = first_bit(low), b = first_bit(low & ~a);

	if (!a || !b || !high) {
		fprintf(stderr, "UNAVAILABLE: need two permitted low bits "
			"and one high bit\n");
		exit(77);
	}
	m = (struct masks) { a, a | b | high, b | high };
	return m;
}

static void failures(void)
{
	struct __user_cap_header_struct h = { 0x12345678, 0 };
	struct __user_cap_data_struct d[2] = { 0 };

	rejected(&h, d, EINVAL);
	h.version = _LINUX_CAPABILITY_VERSION_3;
	rejected((void *)1, d, EFAULT);
	rejected(&h, (void *)1, EFAULT);
	h.pid = -1;
	rejected(&h, d, EPERM);
	h.pid = 0;
	/* This reaches cap_capset but cannot install E outside P. */
	d[0].effective = 1;
	rejected(&h, d, EPERM);
}

static void collision(void)
{
#if defined(__x86_64__)
	long ret;
	/* i386 sigprocmask(0, NULL, NULL), number 126 == native capset.
	 * All pointer arguments are NULL, so no 32-bit address assumptions.
	 */
	__asm__ volatile ("int $0x80" : "=a"(ret) : "0"(126L),
			  "b"(0L), "c"(0L), "d"(0L) : "memory", "cc");
	if (ret != 0) {
		fprintf(stderr, "UNAVAILABLE: i386 syscall ABI unavailable "
			"(return %ld)\n", ret);
		exit(77);
	}
#else
	fprintf(stderr, "SKIP: compat collision fixture requires x86_64\n");
	exit(77);
#endif
}

static void *thread_sets(void *arg)
{
	struct masks m = *(struct masks *)arg;
	int n;

	for (n = 0; n < 32; n++)
		install(m, _LINUX_CAPABILITY_VERSION_3);
	return NULL;
}

static void distinct_threads(void)
{
	struct masks base = get_masks();
	uint64_t a = first_bit(base.p & UINT32_MAX);
	uint64_t b = first_bit((base.p & UINT32_MAX) & ~a);
	struct masks m[2] = { { a, a, 0 }, { 0, b, b } };
	pthread_t threads[2];
	int n;

	if (!a || !b) {
		fprintf(stderr, "UNAVAILABLE: need two permitted low bits\n");
		exit(77);
	}
	for (n = 0; n < 2; n++)
		if (pthread_create(&threads[n], NULL, thread_sets, &m[n]))
			die("pthread_create");
	for (n = 0; n < 2; n++)
		if (pthread_join(threads[n], NULL))
			die("pthread_join");
	if (!equal(base, get_masks())) {
		fprintf(stderr, "Thread-local capset changed leader credentials\n");
		exit(1);
	}
}

static void *mutate_buffer(void *arg)
{
	uint32_t bit = *(uint32_t *)arg;

	while (!atomic_load_explicit(&stop_race, memory_order_relaxed)) {
		__atomic_store_n(&raced[0].effective, bit, __ATOMIC_RELAXED);
		__atomic_store_n(&raced[0].effective, 0, __ATOMIC_RELAXED);
	}
	return NULL;
}

static void race_buffer(void)
{
	struct masks base = get_masks(), m = { 0, base.p, 0 };
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	uint32_t bit = first_bit(base.p & UINT32_MAX);
	pthread_t thread;
	int n;

	if (!bit) {
		fprintf(stderr, "UNAVAILABLE: need a permitted low bit\n");
		exit(77);
	}
	pack(raced, m);
	if (pthread_create(&thread, NULL, mutate_buffer, &bit))
		die("pthread_create");
	for (n = 0; n < 512; n++) {
		if (syscall(SYS_capset, &h, raced))
			die("raced capset");
		observed_success();
	}
	atomic_store(&stop_race, 1);
	if (pthread_join(thread, NULL))
		die("pthread_join");
}

static void compat_capset(void)
{
#if defined(__x86_64__)
	struct {
		struct __user_cap_header_struct h;
		struct __user_cap_data_struct d[2];
	} *args;
	long ret;

	args = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (args == MAP_FAILED)
		die("mmap compat arguments");
	args->h.version = _LINUX_CAPABILITY_VERSION_3;
	/* i386 capset uses syscall 185 and 32-bit userspace pointers. */
	__asm__ volatile ("int $0x80" : "=a"(ret) : "0"(185L),
			  "b"(&args->h), "c"(args->d) : "memory", "cc");
	if (ret == -ENOSYS) {
		fprintf(stderr, "UNAVAILABLE: i386 syscall ABI unavailable\n");
		exit(77);
	}
	if (ret) {
		fprintf(stderr, "compat capset returned %ld\n", ret);
		exit(1);
	}
	observed_success();
	munmap(args, 4096);
#else
	fprintf(stderr, "SKIP: compat fixture requires x86_64\n");
	exit(77);
#endif
}

/* These fixtures use actual task lifecycle synchronization, never sleeps. */
static unsigned long long user_namespace(void)
{
	struct stat st;

	if (stat("/proc/self/ns/user", &st)) {
		/* CONFIG_USER_NS may be absent, or procfs/LSM/seccomp policy
		 * may deny this lookup before unshare is even attempted. Without
		 * an independent namespace inode we cannot validate attribution;
		 * missing evidence is incomplete coverage, not a tracer failure.
		 */
		procfs_failure("stat /proc/self/ns/user");
	}
	return st.st_ino;
}

static void expected_check(int nr, int capability, int granted)
{
	printf("ECHK %u %u %d %d %d %llu\n", (unsigned)getpid(),
	       (unsigned)syscall(SYS_gettid), nr, capability, granted,
	       user_namespace());
	fflush(stdout);
}

static void denied_bounding_check(void)
{
	/* After zeroing E/P/I, this must fail and generate a SETPCAP check.
	 * CHECK events carry TID even though CAPSET events currently do not.
	 */
	if (prctl(PR_CAPBSET_DROP, CAP_CHOWN, 0, 0, 0) != -1 ||
	    errno != EPERM) {
		fprintf(stderr, "Expected bounding-drop failure without SETPCAP\n");
		exit(1);
	}
	expected_check(SYS_prctl, CAP_SETPCAP, 0);
}

static void wait_for_leader_exit(void)
{
	/* On kernels such as 5.14, exit_mm() wakes pthread_join() before
	 * sched_process_exit runs. Joining alone can let the worker's checks
	 * pass before the BPF exit hook has removed the leader's state.
	 * EXIT_ZOMBIE is published later by exit_notify(), after that hook.
	 * /proc/self/status describes the leader, not this surviving worker;
	 * the live worker keeps the leader from being reaped or its PID reused.
	 * The workload alarm bounds this wait without a scheduling-time guess.
	 */
	for (;;) {
		FILE *status = fopen("/proc/self/status", "r");
		char line[256], state = 0;

		if (!status)
			procfs_failure("open leader status");
		while (fgets(line, sizeof(line), status))
			if (sscanf(line, "State: %c", &state) == 1)
				break;
		if (ferror(status))
			procfs_failure("read leader status");
		fclose(status);
		if (!state) {
			fprintf(stderr, "Leader status has no task state\n");
			exit(1);
		}
		if (state == 'Z')
			break;
		sched_yield();
	}
	printf("LIFE leader-zombie %u %u\n", (unsigned)getpid(),
	       (unsigned)getpid());
	fflush(stdout);
}

static void *survive_leader(void *unused)
{
	int rc;
	(void)unused;

	rc = pthread_join(leader, NULL);
	if (rc) {
		errno = rc;
		die("join exited leader");
	}
	wait_for_leader_exit();
	printf("LIFE survivor %u %u\n", (unsigned)getpid(),
	       (unsigned)syscall(SYS_gettid));
	fflush(stdout);
	install((struct masks){ 0 }, _LINUX_CAPABILITY_VERSION_3);
	denied_bounding_check();
	return NULL;
}

static void *exec_worker(void *unused)
{
	(void)unused;
	printf("LIFE before-exec %u %u\n", (unsigned)getpid(),
	       (unsigned)syscall(SYS_gettid));
	fflush(stdout);
	execl("/proc/self/exe", "cap_audit_live", "--work",
	      "worker-exec-child", NULL);
	die("worker exec");
	return NULL;
}

static void thread_lifecycle(int do_exec)
{
	pthread_t worker;
	int rc;

	leader = pthread_self();
	rc = pthread_create(&worker, NULL,
			    do_exec ? exec_worker : survive_leader, NULL);
	if (rc) {
		errno = rc;
		die("create lifecycle worker");
	}
	if (!do_exec)
		pthread_exit(NULL);
	/* Keep the leader alive until exec kills it. */
	for (;;)
		pause();
}

static void foreign_namespace(void)
{
	unsigned long long baseline = user_namespace();
	struct masks m;

	/* All hostname changes are confined to this new UTS namespace. */
	if (unshare(CLONE_NEWUSER | CLONE_NEWUTS)) {
		if (errno == EPERM || errno == EACCES || errno == EINVAL ||
		    errno == ENOSYS || errno == ENOSPC || errno == EUSERS)
			unavailable("private user/UTS namespace");
		die("private user/UTS namespace");
	}
	printf("NAMESPACE %llu %llu\n", baseline, user_namespace());
	fflush(stdout);
	if (syscall(SYS_sethostname, "cap-audit-test", 14)) {
		/* Creating a namespace does not bypass host policy. An LSM or
		 * seccomp filter can still prohibit its first hostname change.
		 * This call establishes that the fixture can run; after E is
		 * dropped below, the expected EPERM remains a tested invariant.
		 * Do not hide unexpected errors (e.g. EFAULT) as missing access.
		 */
		if (errno == EPERM || errno == EACCES || errno == ENOSYS)
			unavailable("sethostname in private namespace");
		die("sethostname in private namespace");
	}
	expected_check(SYS_sethostname, CAP_SYS_ADMIN, 1);
	m = get_masks();
	m.e = 0;
	install(m, _LINUX_CAPABILITY_VERSION_3);
	if (syscall(SYS_sethostname, "denied", 6) != -1 || errno != EPERM) {
		fprintf(stderr, "Expected sethostname failure without SYS_ADMIN\n");
		exit(1);
	}
	expected_check(SYS_sethostname, CAP_SYS_ADMIN, 0);
}

static void workload(const char *mode)
{
	struct masks zero = { 0 };
	int n;

	alarm(30);
	if (!strcmp(mode, "zero") || !strcmp(mode, "preexec") ||
	    !strcmp(mode, "exec")) {
		install(zero, _LINUX_CAPABILITY_VERSION_3);
	} else if (!strcmp(mode, "leader-exit")) {
		thread_lifecycle(0);
	} else if (!strcmp(mode, "worker-exec")) {
		thread_lifecycle(1);
	} else if (!strcmp(mode, "worker-exec-child")) {
		printf("LIFE after-exec %u %u\n", (unsigned)getpid(),
		       (unsigned)syscall(SYS_gettid));
		fflush(stdout);
		install(zero, _LINUX_CAPABILITY_VERSION_3);
		denied_bounding_check();
	} else if (!strcmp(mode, "userns")) {
		foreign_namespace();
	} else if (!strcmp(mode, "mixed")) {
		install(mixed_masks(), _LINUX_CAPABILITY_VERSION_3);
	} else if (!strcmp(mode, "v1")) {
		struct masks m = mixed_masks();
		install(m, _LINUX_CAPABILITY_VERSION_3);
		/* The upper array element contains nonzero data but v1 ignores it. */
		install(m, _LINUX_CAPABILITY_VERSION_1);
	} else if (!strcmp(mode, "v2")) {
		install(mixed_masks(), _LINUX_CAPABILITY_VERSION_2);
	} else if (!strcmp(mode, "noop")) {
		struct masks m = get_masks();
		for (n = 0; n < 8; n++)
			install(m, _LINUX_CAPABILITY_VERSION_3);
	} else if (!strcmp(mode, "unknown-bits")) {
		struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
		struct __user_cap_data_struct d[2] = { 0 };
		FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
		int last;

		if (!f || fscanf(f, "%d", &last) != 1)
			die("cap_last_cap");
		fclose(f);
		if (last >= 63) {
			fprintf(stderr, "UNAVAILABLE: bit 63 is a defined capability\n");
			exit(77);
		}
		d[1].effective = d[1].permitted = d[1].inheritable = 0x80000000U;
		if (syscall(SYS_capset, &h, d))
			die("unknown bits capset");
		if (!equal(zero, get_masks())) {
			fprintf(stderr, "Unknown capability bit was not cleared\n");
			exit(1);
		}
		observed_success();
	} else if (!strcmp(mode, "failures")) {
		failures();
	} else if (!strcmp(mode, "compat-capset")) {
		compat_capset();
	} else if (!strcmp(mode, "collision")) {
		collision();
	} else if (!strcmp(mode, "stale")) {
		install(zero, _LINUX_CAPABILITY_VERSION_3);
		failures();
#if defined(__x86_64__)
		collision();
#endif
		install(zero, _LINUX_CAPABILITY_VERSION_3);
	} else if (!strcmp(mode, "threads")) {
		distinct_threads();
	} else if (!strcmp(mode, "race")) {
		race_buffer();
	} else {
		fprintf(stderr, "Unknown case: %s\n", mode);
		exit(1);
	}
}

/* Use the production event definition and skeleton, not mock field layouts. */
static int event(void *ctx, void *data, size_t size)
{
	const struct cap_event *e = data;
	(void)ctx;
	if (size != sizeof(*e)) {
		fprintf(stderr, "Unexpected BPF event size: %zu\n", size);
		return -EINVAL;
	}
	if (e->event_type == CAP_EVENT_CHECK &&
	    ((!strcmp(trace_case, "userns") &&
	      e->syscall_nr == SYS_sethostname) ||
	     ((!strcmp(trace_case, "leader-exit") ||
	       !strcmp(trace_case, "worker-exec")) &&
	      e->syscall_nr == SYS_prctl)))
		printf("OCHK %u %u %d %d %d %u\n", e->pid, e->tid,
		       e->syscall_nr, e->capability, e->result,
		       e->targ_ns_inum);
	if (e->event_type == CAP_EVENT_CAPSET) {
		if (e->syscall_ret != 0 || e->syscall_nr != expected_nr) {
			fprintf(stderr, "CAPSET event has unexpected syscall "
				"number %d or result %lld\n", e->syscall_nr,
				(long long)e->syscall_ret);
			return -EINVAL;
		}
		record("OBS", e->tid, e->pid, (struct masks) {
			e->capset_effective, e->capset_permitted, e->capset_inheritable });
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct cap_audit_bpf *skel;
	struct ring_buffer *ring;
	struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
	int gate[2], status = 0, err, result = 1;
	pid_t child, done;
	__u32 tid;
	__u8 phase;
	char byte;
	const char *mode;

	if (argc != 3)
		return 2;
	mode = argv[2];
	trace_case = mode;
	if (!strcmp(argv[1], "--work")) {
		workload(mode);
		return 0;
	}
	if (strcmp(argv[1], "--trace") && strcmp(argv[1], "--probe"))
		return 2;
	if (setrlimit(RLIMIT_MEMLOCK, &limit))
		perror("setrlimit (continuing; newer kernels may not need it)");
	skel = cap_audit_bpf__open();
	if (!skel)
		die("open skeleton");
	skel->rodata->prctl_syscall_nr = SYS_prctl;
	err = cap_audit_bpf__load(skel);
	if (!err)
		err = cap_audit_bpf__attach(skel);
	if (err) {
		/* Permission/interface absence is environmental; verifier errors
		 * such as EINVAL must remain failures, not silent skips.
		 */
		result = (err == -EPERM || err == -EACCES || err == -ENOENT ||
			  err == -ENOSYS || err == -EOPNOTSUPP) ? 77 : 1;
		fprintf(stderr, "%s: BPF load/attach: %s (%d); "
			"see libbpf diagnostics above\n",
			result == 77 ? "UNAVAILABLE" : "FAIL", strerror(-err), err);
		goto destroy;
	}
	if (!strcmp(argv[1], "--probe")) {
		puts("PASS: production BPF programs loaded and attached");
		result = 0;
		goto destroy;
	}
	if (!strcmp(mode, "compat-capset"))
		expected_nr = 185;
	ring = ring_buffer__new(bpf_map__fd(skel->maps.cap_events), event, NULL, NULL);
	if (!ring) {
		perror("create event ring buffer");
		goto destroy;
	}
	if (pipe(gate))
		die("pipe");
	child = fork();
	if (child < 0)
		die("fork");
	if (!child) {
		close(gate[1]);
		alarm(30);
		if (read(gate[0], &byte, 1) != 1)
			_exit(1);
		close(gate[0]);
		if (!strcmp(mode, "exec")) {
			emit_expected = 0;
			workload("zero");
			execl("/proc/self/exe", argv[0], "--work", "exec", NULL);
			die("exec self");
		}
		emit_expected = strcmp(mode, "preexec") != 0;
		workload(mode);
		_exit(0);
	}
	close(gate[0]);
	tid = child;
	phase = (!strcmp(mode, "preexec") || !strcmp(mode, "exec") ||
		 !strcmp(mode, "worker-exec")) ? 1 : 2;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.target_pids), &tid,
				&phase, BPF_ANY)) {
		perror("select traced child");
		close(gate[1]);
		waitpid(child, &status, 0);
		goto free_ring;
	}
	if (write(gate[1], "x", 1) != 1)
		die("release child");
	close(gate[1]);
	do {
		err = ring_buffer__poll(ring, 10);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Event poll failed: %s\n", strerror(-err));
			kill(child, SIGKILL);
			waitpid(child, &status, 0);
			goto free_ring;
		}
		done = waitpid(child, &status, WNOHANG);
	} while (!done || (done < 0 && errno == EINTR));
	cap_audit_bpf__detach(skel);
	if (done < 0 || ring_buffer__consume(ring) < 0)
		goto free_ring;
	if (skel->bss->lost_map_updates || skel->bss->lost_ring_events ||
	    skel->bss->lost_capset_reads) {
		fprintf(stderr, "Production BPF lost observations\n");
		goto free_ring;
	}
	result = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
	if (!result && (!strcmp(mode, "leader-exit") ||
			!strcmp(mode, "worker-exec"))) {
		/* Once waitpid reaps the task, no per-task entries may remain. */
		int fds[] = { bpf_map__fd(skel->maps.target_pids),
			      bpf_map__fd(skel->maps.current_syscalls),
			      bpf_map__fd(skel->maps.cap_events_inflight) };
		unsigned int i;
		__u64 key;

		for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
			if (bpf_map_get_next_key(fds[i], NULL, &key) == 0 ||
			    errno != ENOENT) {
				fprintf(stderr, "Task state map %u not empty "
					"after exit\n", i);
				result = 1;
			}
		}
		if (!result)
			puts("CLEANUP empty");
	}
free_ring:
	ring_buffer__free(ring);
destroy:
	cap_audit_bpf__destroy(skel);
	return result;
}
