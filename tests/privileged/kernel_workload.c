// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel integration fixtures. Each invocation runs in a disposable process;
 * no mocks replace libcap-ng, procfs, or capability syscalls.
 */
#include "config.h"
#include "cap-ng.h"
#include <errno.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct masks { uint64_t e, p, i; };

static void fail(const char *operation)
{
	fprintf(stderr, "FAIL: %s: errno=%d (%s)\n", operation, errno,
		strerror(errno));
	exit(1);
}

static void unavailable(const char *operation)
{
	fprintf(stderr, "UNAVAILABLE: %s: errno=%d (%s)\n", operation,
		errno, strerror(errno));
	exit(77);
}

static void require(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s\n", message);
		exit(1);
	}
}

static struct masks kernel_masks(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2] = { 0 };

	if (syscall(SYS_capget, &h, d))
		fail("capget");
	return (struct masks) {
		d[0].effective | ((uint64_t)d[1].effective << 32),
		d[0].permitted | ((uint64_t)d[1].permitted << 32),
		d[0].inheritable | ((uint64_t)d[1].inheritable << 32)
	};
}

static void compare_snapshot(void)
{
	struct masks m = kernel_masks();
	unsigned int bit;

	if (capng_get_caps_process())
		fail("capng_get_caps_process");
	for (bit = 0; bit < 64; bit++) {
		int bound = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
#ifdef PR_CAP_AMBIENT
		int ambient;
#endif

		if (bound < 0 && errno != EINVAL)
			fail("PR_CAPBSET_READ");
		require(capng_have_capability(CAPNG_EFFECTIVE, bit) ==
			!!(m.e & (1ULL << bit)), "effective set differs from capget");
		require(capng_have_capability(CAPNG_PERMITTED, bit) ==
			!!(m.p & (1ULL << bit)), "permitted set differs from capget");
		require(capng_have_capability(CAPNG_INHERITABLE, bit) ==
			!!(m.i & (1ULL << bit)), "inheritable set differs from capget");
		/* Include metadata sets: the no-procfs fallback must recover
		 * these from prctl, not silently replace them with empty sets.
		 */
		require(capng_have_capability(CAPNG_BOUNDING_SET, bit) ==
			(bound == 1), "bounding set differs from prctl");
#ifdef PR_CAP_AMBIENT
		ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0);

		if (ambient < 0 && errno != EINVAL)
			fail("PR_CAP_AMBIENT_IS_SET");
		require(capng_have_capability(CAPNG_AMBIENT, bit) ==
			(ambient == 1), "ambient set differs from prctl");
#endif
	}
}

static int available_bit(void)
{
	struct masks m = kernel_masks();
	unsigned int bit;

	for (bit = 0; bit < 64; bit++)
		if ((m.p & (1ULL << bit)) &&
		    prctl(PR_CAPBSET_READ, bit, 0, 0, 0) == 1)
			return bit;
	errno = EPERM;
	unavailable("no capability in both permitted and bounding sets");
	return -1;
}

static void mount_namespace(void)
{
	if (unshare(CLONE_NEWNS))
		unavailable("unshare(CLONE_NEWNS)");
	/* Propagation must be private before covering /proc. */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		unavailable("make mount propagation private");
}

static void procfs_recovery(void)
{
	pid_t child;
	int gate[2], status, rc, error;
	char byte;

	mount_namespace();
	if (mount("tmpfs", "/proc", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
		  "size=64k"))
		unavailable("mount private tmpfs over /proc");
	if (pipe(gate))
		fail("pipe");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		close(gate[1]);
		/* EOF also releases the child if the parent fails or is killed. */
		(void)read(gate[0], &byte, 1);
		_exit(0);
	}
	close(gate[0]);
	capng_setpid(0);
	compare_snapshot();
	capng_setpid(child);
	errno = 0;
	rc = capng_get_caps_process();
	error = errno;
	close(gate[1]);
	if (waitpid(child, &status, 0) != child)
		fail("waitpid");
	require(rc == -1 && error == ENOENT,
		"remote read without procfs did not fail with ENOENT");
	capng_clear(CAPNG_SELECT_ALL);
	capng_setpid(0);
	compare_snapshot();
	puts("PASS: real remote metadata failure followed by self fallback");
}

static void exited_target(void)
{
	pid_t child = fork();
	int status, rc, error;

	if (child < 0)
		fail("fork");
	if (!child)
		_exit(0);
	if (waitpid(child, &status, 0) != child)
		fail("waitpid");
	capng_setpid(child);
	errno = 0;
	rc = capng_get_caps_process();
	error = errno;
	require(rc == -1 && error == ESRCH, "reaped target did not give ESRCH");
	capng_clear(CAPNG_SELECT_ALL);
	capng_setpid(0);
	compare_snapshot();
	puts("PASS: real target exit did not poison subsequent reads");
}

static void *thread_caps(void *unused)
{
	struct masks leader = kernel_masks();
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2] = { 0 };
	(void)unused;

	/* Raw capset changes just this worker. Keep the leader's sets intact. */
	if (syscall(SYS_capset, &h, d))
		fail("worker capset");
	capng_setpid(0);
	compare_snapshot();
	capng_setpid(getpid());
	if (capng_get_caps_process())
		fail("read leader from worker");
	for (unsigned int bit = 0; bit < 64; bit++)
		require(capng_have_capability(CAPNG_PERMITTED, bit) ==
			!!(leader.p & (1ULL << bit)), "leader confused with worker");
	return NULL;
}

static void threads(void)
{
	pthread_t worker;
	struct masks before = kernel_masks(), after;
	int rc;

	if (!before.p) {
		errno = EPERM;
		unavailable("thread test needs nonempty leader capabilities");
	}
	rc = pthread_create(&worker, NULL, thread_caps, NULL);
	if (rc) {
		errno = rc;
		fail("pthread_create");
	}
	rc = pthread_join(worker, NULL);
	if (rc) {
		errno = rc;
		fail("pthread_join");
	}
	after = kernel_masks();
	require(before.e == after.e && before.p == after.p && before.i == after.i,
		"worker changed leader credentials");
	puts("PASS: kernel thread credentials and remote leader reads agree");
}

static void bounding(void)
{
	int bit = available_bit();

	if (!(kernel_masks().e & (1ULL << CAP_SETPCAP))) {
		errno = EPERM;
		unavailable("bounding drop requires effective CAP_SETPCAP");
	}
	if (capng_get_caps_process() ||
	    capng_update(CAPNG_DROP, CAPNG_BOUNDING_SET, bit) ||
	    capng_apply(CAPNG_SELECT_BOUNDS))
		fail("libcap-ng bounding drop");
	require(prctl(PR_CAPBSET_READ, bit, 0, 0, 0) == 0,
		"bounding drop did not reach the kernel");
	if (capng_get_caps_process())
		fail("read dropped bounding set");
	require(!capng_have_capability(CAPNG_BOUNDING_SET, bit),
		"procfs read did not reflect bounding drop");
	puts("PASS: library bounding drop agrees with prctl and procfs");
}

static void ambient_exec(const char *self)
{
#ifdef PR_CAP_AMBIENT
	int bit = available_bit();
	char value[16];

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0) < 0)
		unavailable("PR_CAP_AMBIENT_IS_SET");
	if (!(kernel_masks().e & (1ULL << CAP_SETPCAP))) {
		errno = EPERM;
		unavailable("ambient exec fixture requires CAP_SETPCAP");
	}
	/* Disable root's exec capability expansion so the ambient set is the
	 * independent reason this single bit becomes permitted and effective.
	 */
	if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
		  0, 0, 0))
		unavailable("PR_SET_SECUREBITS for ambient exec fixture");
	if (capng_get_caps_process())
		fail("read ambient setup state");
	capng_clear(CAPNG_SELECT_CAPS | CAPNG_SELECT_AMBIENT);
	if (capng_update(CAPNG_ADD, CAPNG_PERMITTED | CAPNG_INHERITABLE |
			 CAPNG_AMBIENT, bit) ||
	    capng_apply(CAPNG_SELECT_CAPS | CAPNG_SELECT_AMBIENT))
		fail("apply ambient fixture");
	snprintf(value, sizeof(value), "%d", bit);
	execl(self, self, "ambient-child", value, NULL);
	fail("exec ambient child");
#else
	(void)self;
	errno = ENOSYS;
	unavailable("ambient support absent from build headers");
#endif
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	alarm(30);
	if (!strcmp(argv[1], "probe-exec")) {
		struct __user_cap_header_struct h = {
			_LINUX_CAPABILITY_VERSION_3, 0
		};
		struct __user_cap_data_struct d[2] = { 0 };

		/* Real root stops bypassing build-user permissions after capset.
		 * Use the full staged path so inaccessible ancestors and noexec
		 * mounts are diagnosed before the exec-sensitive tests run.
		 */
		if (syscall(SYS_capset, &h, d))
			unavailable("drop capabilities for exec probe");
		execl(argv[0], argv[0], "exec-child", NULL);
		unavailable("execute staged helper without DAC capabilities");
	} else if (!strcmp(argv[1], "exec-child")) {
		puts("PASS: staged helper executable without DAC capabilities");
	} else if (!strcmp(argv[1], "probe-mount")) {
		mount_namespace();
		puts("PASS: private mount namespace available");
	} else if (!strcmp(argv[1], "probe-caps")) {
		int bit = available_bit();

		if (!(kernel_masks().e & (1ULL << CAP_SETPCAP))) {
			errno = EPERM;
			unavailable("effective CAP_SETPCAP for bounding/ambient tests");
		}
#ifdef PR_CAP_AMBIENT
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0) < 0)
			unavailable("ambient capability interface");
#else
		(void)bit;
		errno = ENOSYS;
		unavailable("ambient support absent from build headers");
#endif
		puts("PASS: capability transition prerequisites available");
	} else if (!strcmp(argv[1], "procfs"))
		procfs_recovery();
	else if (!strcmp(argv[1], "exit"))
		exited_target();
	else if (!strcmp(argv[1], "threads"))
		threads();
	else if (!strcmp(argv[1], "bounding"))
		bounding();
	else if (!strcmp(argv[1], "ambient"))
		ambient_exec("/proc/self/exe");
	else if (!strcmp(argv[1], "ambient-child") && argc == 3) {
		unsigned int bit = strtoul(argv[2], NULL, 10);
		struct masks m = kernel_masks();

		require(bit < 64, "invalid ambient fixture bit");
		require(m.e == (1ULL << bit) && m.p == (1ULL << bit) &&
			m.i == (1ULL << bit), "ambient exec installed wrong masks");
		compare_snapshot();
		require(capng_have_capability(CAPNG_AMBIENT, bit),
			"ambient bit lost across exec");
		puts("PASS: ambient exec propagation matches kernel credentials");
	} else
		return 2;
	return 0;
}
