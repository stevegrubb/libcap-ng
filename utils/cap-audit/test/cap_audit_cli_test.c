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
