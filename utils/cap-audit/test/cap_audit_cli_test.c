// SPDX-License-Identifier: GPL-2.0-or-later
/* Run the real launch/report path with an unprivileged BPF transport fixture. */
#include "cap_audit.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum fixture_mode {
	NORMAL, POLL_ERROR, DRAIN_ERROR, MAP_LOSS, RING_LOSS, READ_LOSS,
	DESCENDANTS, NO_EXEC, REQUESTED_STOP, SERVICE_ERROR,
};
static enum fixture_mode mode;
static struct cap_audit_bpf fixture_skel;
static struct cap_audit_bpf__bss fixture_bss;
static struct cap_audit_bpf__rodata fixture_rodata;

static struct cap_audit_bpf *fixture_open(void)
{
	fixture_skel.bss = &fixture_bss;
	fixture_skel.rodata = &fixture_rodata;
	fixture_bss.initial_exec_seen = mode != NO_EXEC;
	fixture_bss.lost_map_updates = mode == MAP_LOSS;
	fixture_bss.lost_ring_events = mode == RING_LOSS;
	fixture_bss.lost_capset_reads = mode == READ_LOSS;
	return &fixture_skel;
}

static int fixture_start(struct cap_audit_bpf *skel)
{
	(void)skel;
	return 0;
}

static void fixture_destroy(struct cap_audit_bpf *skel)
{
	(void)skel;
}

static int fixture_map_fd(const struct bpf_map *map)
{
	(void)map;
	return 7;
}

static int fixture_select(int fd, const void *key, const void *value,
			  __u64 flags)
{
	(void)fd; (void)key; (void)value; (void)flags;
	return 0;
}

static int fixture_next(int fd, const void *key, void *next)
{
	(void)fd; (void)key; (void)next;
	errno = ENOENT;
	return mode == DESCENDANTS ? 0 : -1;
}

static struct ring_buffer *fixture_ring(int fd, ring_buffer_sample_fn callback,
				       void *ctx, const struct ring_buffer_opts *opts)
{
	(void)fd; (void)callback; (void)ctx; (void)opts;
	return (struct ring_buffer *)&fixture_skel;
}

static int fixture_poll(struct ring_buffer *ring, int timeout)
{
	(void)ring; (void)timeout;
	if (mode == REQUESTED_STOP)
		state.stop = SIGINT;
	usleep(1000);
	return mode == POLL_ERROR ? -EIO : 0;
}

static int fixture_consume(struct ring_buffer *ring)
{
	(void)ring;
	return mode == DRAIN_ERROR ? -EIO : 0;
}

static void fixture_free_ring(struct ring_buffer *ring)
{
	(void)ring;
}

static int fixture_limit(int resource, const struct rlimit *limit)
{
	(void)resource; (void)limit;
	return 0;
}

static int fixture_cap(capng_type_t type, unsigned int cap)
{
	(void)type; (void)cap;
	return 1;
}

static int fixture_service(const service_config_t *cfg)
{
	(void)cfg;
	errno = EPERM;
	return mode == SERVICE_ERROR ? -1 : 0;
}

#define cap_audit_bpf__open fixture_open
#define cap_audit_bpf__load fixture_start
#define cap_audit_bpf__attach fixture_start
#define cap_audit_bpf__detach fixture_destroy
#define cap_audit_bpf__destroy fixture_destroy
#define bpf_map__fd fixture_map_fd
#define bpf_map_update_elem fixture_select
#define bpf_map_get_next_key fixture_next
#define ring_buffer__new fixture_ring
#define ring_buffer__poll fixture_poll
#define ring_buffer__consume fixture_consume
#define ring_buffer__free fixture_free_ring
#define setrlimit fixture_limit
#define capng_have_capability fixture_cap
#define apply_service_config fixture_service
#define main cap_audit_main
#include "../cap_audit.c"
#undef main

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(1);
}

static void run_case(char **args, int expected, const char *field)
{
	FILE *capture = tmpfile();
	pid_t child;
	int status, argc = 0;
	char output[32768];
	size_t size;

	while (args[argc])
		argc++;
	if (!capture || fflush(NULL))
		fail("Cannot prepare CLI capture");
	child = fork();
	if (child < 0)
		fail("Cannot fork CLI test");
	if (!child) {
		alarm(10);
		if (dup2(fileno(capture), STDOUT_FILENO) < 0)
			_exit(3);
		exit(cap_audit_main(argc, args));
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != expected)
		fail("CLI returned an incorrect collection status");
	rewind(capture);
	size = fread(output, 1, sizeof(output) - 1, capture);
	output[size] = 0;
	if ((!strcmp(args[1], "-j") || !strcmp(args[1], "-y")) &&
	    (strstr(output, "WORKLOAD-OUTPUT") ||
	     (!strcmp(args[1], "-j") && output[0] != '{') ||
	     (!strcmp(args[1], "-y") && strncmp(output, "schema_version:", 15))))
		fail("Machine report stream contains workload or progress output");
	if (ferror(capture) || fgetc(capture) != EOF || !strstr(output, field)) {
		fprintf(stderr, "%s\n", output);
		fail(field);
	}
	fclose(capture);
}

/* Expect a setup failure before tracing and a specific stderr message. */
static void run_rejected(char **args, const char *message)
{
	FILE *errors = tmpfile();
	pid_t child;
	int status, argc = 0;
	char output[4096];
	size_t size;

	while (args[argc])
		argc++;
	if (!errors || fflush(NULL))
		fail("Cannot prepare CLI error capture");
	child = fork();
	if (child < 0)
		fail("Cannot fork CLI test");
	if (!child) {
		alarm(10);
		if (dup2(fileno(errors), STDERR_FILENO) < 0)
			_exit(3);
		exit(cap_audit_main(argc, args));
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 1)
		fail("CLI did not reject the selected service command");
	rewind(errors);
	size = fread(output, 1, sizeof(output) - 1, errors);
	output[size] = 0;
	if (!strstr(output, message)) {
		fprintf(stderr, "%s\n", output);
		fail(message);
	}
	fclose(errors);
}

static void write_unit(char *path, const char *contents)
{
	size_t len = strlen(contents);
	int fd = mkstemp(path);

	if (fd < 0 || write(fd, contents, len) != (ssize_t)len || close(fd))
		fail("Cannot prepare service fixture");
}

/*
 * test_service_overrides - check ExecStart expansions only where they run.
 *
 * Unit words replaced by an explicit command or argument override are never
 * executed, so their unsupported expansions must not block the audit. The
 * distinct exit statuses prove which arguments the traced workload received.
 */
static void test_service_overrides(void)
{
	char args_unit[] = "/tmp/cap-audit-args-XXXXXX";
	char env_unit[] = "/tmp/cap-audit-env-XXXXXX";
	char path_unit[] = "/tmp/cap-audit-path-XXXXXX";
	char *full[] = { "cap-audit", "-j", "--service", args_unit, "--",
			 "/bin/sh", "-c", "exit 5", NULL };
	char *replace[] = { "cap-audit", "-j", "--service", args_unit, "--",
			    "-c", "exit 7", NULL };
	char *strict[] = { "cap-audit", "-j", "--service", args_unit, NULL };
	char *env_replace[] = { "cap-audit", "-j", "--service", env_unit,
				"--", "-c", "exit 9", NULL };
	char *env_strict[] = { "cap-audit", "-j", "--service", env_unit, NULL };
	char *path_replace[] = { "cap-audit", "-j", "--service", path_unit,
				 "--", "-c", "exit 0", NULL };

	write_unit(args_unit, "[Service]\nExecStart=/bin/sh %i -c true\n");
	write_unit(env_unit, "[Service]\nExecStart=/bin/sh ${FOO}\n");
	write_unit(path_unit, "[Service]\nExecStart=/bin/%n -c true\n");

	mode = NORMAL;
	run_case(full, 0, "\"target_exit_status\": 5");
	run_case(replace, 0, "\"target_exit_status\": 7");
	run_case(env_replace, 0, "\"target_exit_status\": 9");
	/* Without an override, every unit word executes and is checked. */
	run_rejected(strict, "ExecStart specifiers such as %i are unsupported");
	run_rejected(env_strict, "ExecStart ${NAME} expansion is unsupported");
	/* Replacement arguments still execute the unit's own executable. */
	run_rejected(path_replace,
		     "ExecStart specifiers such as %i are unsupported");

	if (unlink(args_unit) || unlink(env_unit) || unlink(path_unit))
		fail("Cannot remove service fixtures");
}

/* A dynamic user's implied NoNewPrivileges must reach every report line. */
static void test_dynamic_user_report(void)
{
	char dyn_unit[] = "/tmp/cap-audit-dynamic-XXXXXX";
	char *report[] = { "cap-audit", "--service", dyn_unit, NULL };

	write_unit(dyn_unit, "[Service]\nDynamicUser=yes\n"
		   "NoNewPrivileges=no\nExecStart=/bin/true\n");
	mode = NORMAL;
	run_case(report, 0, "NoNewPrivileges: yes (implied by DynamicUser=yes)");
	run_case(report, 0, "    NoNewPrivileges=yes\n");
	if (unlink(dyn_unit))
		fail("Cannot remove service fixture");
}

/* Read one decimal process ID written by the traced shell. */
static pid_t read_pid_file(const char *path)
{
	FILE *file = fopen(path, "r");
	long pid = 0;

	if (!file || fscanf(file, "%ld", &pid) != 1 || pid <= 0)
		fail("Cannot read traced process ID");
	fclose(file);
	return (pid_t)pid;
}

/* Return the parent PID from /proc/<pid>/stat, or -1 if unavailable. */
static pid_t read_ppid(pid_t pid)
{
	char path[64], buf[512], *close_paren;
	FILE *file;
	long ppid;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	file = fopen(path, "r");
	if (!file)
		return -1;
	if (!fgets(buf, sizeof(buf), file)) {
		fclose(file);
		return -1;
	}
	fclose(file);
	/* The command name is parenthesized and may contain spaces. */
	close_paren = strrchr(buf, ')');
	if (!close_paren || sscanf(close_paren + 1, " %*c %ld", &ppid) != 1)
		return -1;
	return (pid_t)ppid;
}

/*
 * test_follow_descendants - keep tracing a descendant that outlives its
 * parent.
 *
 * The target starts a background process that blocks on a FIFO and exits.
 * The test checks reparenting directly instead of timing: once the target
 * is gone, the background process must be cap-audit's child, and cap-audit
 * must still be running. Releasing the FIFO then ends the trace.
 */
static void test_follow_descendants(void)
{
	char dir[] = "/tmp/cap-audit-follow-XXXXXX";
	char fifo[64], target_pid[64], descendant_pid[64], script[512];
	char *args[] = { "cap-audit", "-j", "--follow-descendants", "--",
			 "/bin/sh", "-c", script, NULL };
	FILE *capture = tmpfile();
	char output[32768];
	pid_t child, target, descendant;
	size_t size;
	int status, fd, i;

	if (!capture || !mkdtemp(dir))
		fail("Cannot prepare follow fixture");
	snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
	snprintf(target_pid, sizeof(target_pid), "%s/target", dir);
	snprintf(descendant_pid, sizeof(descendant_pid), "%s/descendant", dir);
	if (mkfifo(fifo, 0600))
		fail("Cannot create follow FIFO");
	snprintf(script, sizeof(script),
		 "echo $$ > %s; cat %s > /dev/null & echo $! > %s; exit 0",
		 target_pid, fifo, descendant_pid);

	mode = NORMAL;
	if (fflush(NULL))
		fail("Cannot prepare follow capture");
	child = fork();
	if (child < 0)
		fail("Cannot fork follow test");
	if (!child) {
		alarm(20);
		if (dup2(fileno(capture), STDOUT_FILENO) < 0)
			_exit(3);
		exit(cap_audit_main(7, args));
	}

	/*
	 * A non-blocking open succeeds once the descendant has opened the
	 * FIFO for reading. Retry, but fail instead of hanging if cap-audit
	 * exits first.
	 */
	for (i = 0; ; i++) {
		fd = open(fifo, O_WRONLY | O_NONBLOCK);
		if (fd >= 0)
			break;
		if (errno != ENXIO || i == 1000 ||
		    waitpid(child, &status, WNOHANG) != 0)
			fail("Follow descendant did not start under cap-audit");
		usleep(10000);
	}
	target = read_pid_file(target_pid);
	descendant = read_pid_file(descendant_pid);
	/* Wait for the observable exit of the initial target. */
	for (i = 0; i < 1000 && kill(target, 0) == 0; i++)
		usleep(10000);
	if (kill(target, 0) == 0)
		fail("Initial follow target did not exit");
	if (read_ppid(descendant) != child)
		fail("Orphaned descendant was not adopted by cap-audit");
	if (waitpid(child, &status, WNOHANG) != 0)
		fail("cap-audit stopped before its descendants exited");

	/* EOF on the FIFO lets the last descendant exit. */
	close(fd);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		fail("Followed trace returned an incorrect status");
	rewind(capture);
	size = fread(output, 1, sizeof(output) - 1, capture);
	output[size] = 0;
	fclose(capture);
	if (!strstr(output, "\"descendants_followed\": true") ||
	    !strstr(output, "\"collection_complete\": true") ||
	    !strstr(output, "\"target_exit_status\": 0")) {
		fprintf(stderr, "%s\n", output);
		fail("Followed trace report is incomplete");
	}
	if (unlink(fifo) || unlink(target_pid) || unlink(descendant_pid) ||
	    rmdir(dir))
		fail("Cannot remove follow fixture");
}

int main(void)
{
	char *json[] = { "cap-audit", "-j", "--", "/bin/sh", "-c",
			"printf 'WORKLOAD-OUTPUT\\n'; exit 23", NULL };
	char *yaml[] = { "cap-audit", "-y", "--", "/bin/sh", "-c",
			"printf 'WORKLOAD-OUTPUT\\n'; exit 0", NULL };
	char *text[] = { "cap-audit", "--", "/bin/sh", "-c", "exit 0", NULL };
	char invalid[] = "/tmp/cap-audit-invalid-XXXXXX";
	char unit[] = "/tmp/cap-audit-unit-XXXXXX";
	char *bad_exec[] = { "cap-audit", "-j", "--", invalid, NULL };
	char *bad_service[] = { "cap-audit", "-j", "--service", unit, NULL };
	const char script[] = "#!/missing-cap-audit-interpreter\n";
	const char service[] = "[Service]\nExecStart=/bin/true\n";
	int fd = mkstemp(invalid);

	if (fd < 0 || write(fd, script, sizeof(script) - 1) != sizeof(script) - 1 ||
	    fchmod(fd, 0700) || close(fd))
		fail("Cannot prepare missing-interpreter fixture");
	run_case(json, 0, "\"target_exit_status\": 23");
	run_case(yaml, 0, "collection_complete: true");
	run_case(bad_exec, 2, "\"launch_error\": 2");
	if (unlink(invalid))
		fail("Cannot remove exec fixture");
	for (mode = POLL_ERROR; mode <= REQUESTED_STOP; mode++) {
		run_case(json, 2, "\"collection_complete\": false");
		run_case(text, 2, "Observation is incomplete");
	}
	test_service_overrides();
	test_follow_descendants();
	test_dynamic_user_report();
	fd = mkstemp(unit);
	if (fd < 0 || write(fd, service, sizeof(service) - 1) != sizeof(service) - 1 ||
	    close(fd))
		fail("Cannot prepare service fixture");
	mode = SERVICE_ERROR;
	run_case(bad_service, 2, "\"launch_error\": 22");
	if (unlink(unit))
		fail("Cannot remove service fixture");
	puts("cap-audit CLI collection tests passed");
	return 0;
}
