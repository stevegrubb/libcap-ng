// SPDX-License-Identifier: GPL-2.0-or-later
/* Exercise pscap's own node formatting without depending on host processes. */
#include <sys/prctl.h>
#include <sys/wait.h>
#define main pscap_main
#include "../pscap.c"
#undef main

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}

/*
 * run_pscap - run pscap's main in a child and capture its standard output.
 * @args: NULL-terminated argument vector, starting with the program name.
 * @output: destination for the captured text.
 * @size: capacity of @output.
 *
 * pscap exits from usage(), so it cannot run in this process. Returns the
 * exit status.
 */
static int run_pscap(char **args, char *output, size_t size)
{
	FILE *capture = tmpfile();
	int argc = 0, status;
	pid_t child;
	size_t len;

	while (args[argc])
		argc++;
	if (!capture || fflush(NULL))
		fail("Cannot prepare pscap capture");
	child = fork();
	if (child < 0)
		fail("Cannot fork pscap");
	if (!child) {
		if (dup2(fileno(capture), STDOUT_FILENO) < 0)
			_exit(99);
		exit(pscap_main(argc, args));
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		fail("pscap did not exit normally");
	rewind(capture);
	len = fread(output, 1, size - 1, capture);
	output[len] = '\0';
	fclose(capture);
	return WEXITSTATUS(status);
}

/*
 * test_pscap_main - scan /proc for a known process and check the options.
 *
 * pscap skips its own PID, so a child with a distinctive name and no
 * capabilities is the target, and only -a lists it. Returns no value.
 */
static void test_pscap_main(void)
{
	char pid_text[16], output[8192], expected[64];
	char *tree_all[] = { "pscap", "--tree", "-a", "-p", pid_text, NULL };
	char *tree[] = { "pscap", "--tree", "-p", pid_text, NULL };
	char *plain[] = { "pscap", "-p", pid_text, NULL };
	char *bad_pid[] = { "pscap", "-p", "0", NULL };
	char *bad_text[] = { "pscap", "-p", "12x", NULL };
	char *missing[] = { "pscap", "-p", NULL };
	char *unknown[] = { "pscap", "--bogus", NULL };
	int ready[2], hold[2];
	pid_t target;
	char byte;

	if (pipe(ready) || pipe(hold))
		fail("Cannot create pscap target pipes");
	target = fork();
	if (target < 0)
		fail("Cannot fork pscap target");
	if (!target) {
		close(ready[0]);
		close(hold[1]);
		if (prctl(PR_SET_NAME, "pscap-target", 0, 0, 0))
			_exit(1);
		/*
		 * Dropping capabilities is always allowed, so the target has
		 * none even when the test runs as root, as in CI containers.
		 */
		capng_clear(CAPNG_SELECT_CAPS);
		if (capng_apply(CAPNG_SELECT_CAPS))
			_exit(1);
		/* Report readiness only after the name is visible in /proc. */
		if (write(ready[1], "1", 1) != 1)
			_exit(1);
		while (read(hold[0], &byte, 1) > 0)
			;
		_exit(0);
	}
	close(ready[1]);
	close(hold[0]);
	if (read(ready[0], &byte, 1) != 1)
		fail("pscap target did not start");
	snprintf(pid_text, sizeof(pid_text), "%d", (int)target);
	snprintf(expected, sizeof(expected), "pscap-target(%d:", (int)target);

	if (run_pscap(tree_all, output, sizeof(output)) != 0 ||
	    !strstr(output, expected))
		fail("pscap -a --tree did not list the target process");
	/* Without -a, a process with no capabilities is not listed. */
	if (run_pscap(tree, output, sizeof(output)) != 0 ||
	    strstr(output, "pscap-target"))
		fail("pscap --tree listed a process without capabilities");
	if (run_pscap(plain, output, sizeof(output)) != 0 ||
	    strstr(output, "pscap-target"))
		fail("pscap listed a process without capabilities");
	if (run_pscap(bad_pid, output, sizeof(output)) != 1 ||
	    run_pscap(bad_text, output, sizeof(output)) != 1 ||
	    run_pscap(missing, output, sizeof(output)) != 1 ||
	    run_pscap(unknown, output, sizeof(output)) != 1)
		fail("pscap accepted invalid arguments");

	close(hold[1]);
	close(ready[0]);
	if (waitpid(target, NULL, 0) != target)
		fail("Cannot reap pscap target");
}

int main(void)
{
	const char *expected =
		"worker(12345:codex) [none]\n"
		"\\x1B\\x1B\\x1B\\x1B\\x1B"
		"\\x1B\\x1B\\x1B\\x1B\\x1B"
		"\\x1B\\x1B\\x1B\\x1B\\x1B"
		"(12345:account-name-at-the-buffer-edge) "
		"[cap_chown, cap_net_raw]\n";
	struct proc_info proc = {
		.pid = 12345, .cmd = "worker", .account = "codex",
		.caps_text = "none"
	};
	struct proc_tree tree = { &proc, 1, 240 };
	char comm[16], output[512];
	char *escaped;
	FILE *file = tmpfile();
	int saved = dup(STDOUT_FILENO);
	size_t len;

	if (!file || saved < 0 || fflush(stdout) ||
	    dup2(fileno(file), STDOUT_FILENO) < 0)
		fail("Cannot capture pscap output");
	print_tree_node(&tree, &proc, NULL, true);

	/* A legal 15-byte comm can expand to 60 bytes after escaping. */
	memset(comm, '\033', sizeof(comm) - 1);
	comm[sizeof(comm) - 1] = '\0';
	escaped = sanitize_untrusted_field(comm);
	if (!escaped)
		fail("Cannot escape process name");
	proc.cmd = escaped;
	strcpy(proc.account, "account-name-at-the-buffer-edge");
	proc.caps_text = "cap_chown, cap_net_raw";
	print_tree_node(&tree, &proc, NULL, true);
	free(escaped);

	if (fflush(stdout) || dup2(saved, STDOUT_FILENO) < 0)
		fail("Cannot restore stdout");
	close(saved);
	rewind(file);
	len = fread(output, 1, sizeof(output) - 1, file);
	output[len] = '\0';
	fclose(file);
	if (strcmp(output, expected)) {
		fprintf(stderr, "Expected:\n%sActual:\n%s", expected, output);
		fail("Process name, PID, account, or capabilities were truncated");
	}
	test_pscap_main();
	return 0;
}
