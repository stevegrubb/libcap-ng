// SPDX-License-Identifier: GPL-2.0-or-later
/* Test the real collector and renderer without depending on host sockets. */
#include "../netcap-advanced.c"
#include <sys/prctl.h>

static void fail(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}

static int capability_case;

/* Keep the actual libcap-ng set queries, with deterministic process sets. */
int __wrap_capng_get_caps_process(void)
{
	int cap;

	capng_clear(CAPNG_SELECT_ALL);
	if (capability_case == 4) {
		errno = EACCES;
		return -1;
	}
	if (capability_case == 3) {
		capng_fill(CAPNG_SELECT_CAPS);
		for (cap = 0; cap <= CAP_LAST_CAP; cap++)
			if (capng_update(CAPNG_DROP, CAPNG_EFFECTIVE, cap))
				fail("Cannot clear effective capability fixture");
	} else if (capability_case) {
		capng_type_t type = CAPNG_PERMITTED;

		if (capability_case == 2) {
			type |= CAPNG_EFFECTIVE;
			if (capng_update(CAPNG_ADD, CAPNG_PERMITTED |
					 CAPNG_AMBIENT, CAP_CHOWN))
				fail("Cannot stage second capability");
		}
		if (capng_update(CAPNG_ADD, type, CAP_NET_RAW))
			fail("Cannot stage permitted capability fixture");
	}
	return 0;
}

/* When set, simulate a kernel one capability newer than the build headers. */
static int newer_kernel_cap;

int __real_capng_have_capability(capng_type_t which, unsigned int capability);
int __wrap_capng_have_capability(capng_type_t which, unsigned int capability)
{
	if (newer_kernel_cap && capability == CAP_LAST_CAP + 1)
		return which == CAPNG_PERMITTED;
	return __real_capng_have_capability(which, capability);
}

const char *__real_capng_capability_to_name(unsigned int capability);
const char *__wrap_capng_capability_to_name(unsigned int capability)
{
	static char name[32];

	if (newer_kernel_cap && capability > CAP_LAST_CAP) {
		if (capability > CAP_LAST_CAP + 1)
			return NULL;
		snprintf(name, sizeof(name), "cap_%u", capability);
		return name;
	}
	return __real_capng_capability_to_name(capability);
}

/* A capability newer than the build must not disappear from the summary. */
static void test_newer_kernel_capability(void)
{
	struct process_info p = { .pid = getpid() };
	char expected[64];

	snprintf(expected, sizeof(expected), "net_raw, cap_%u",
		 CAP_LAST_CAP + 1);
	capability_case = 1;
	newer_kernel_cap = 1;
	collect_process_caps(&p);
	newer_kernel_cap = 0;
	if (!p.caps || strcmp(p.caps, expected))
		fail("Capability newer than the build was omitted");
	free(p.caps);
	free(p.ambient_caps);
}

static void test_permitted_summary(void)
{
	static const char *const expected[] = {
		"(none)", "net_raw", "chown, net_raw", "(full)",
	};

	for (capability_case = 0; capability_case < 4; capability_case++) {
		struct process_info p = { .pid = getpid() };

		collect_process_caps(&p);
		if (!p.caps || strcmp(p.caps, expected[capability_case]))
			fail("Capability summary did not report the permitted set");
		if (p.has_privileged_caps != (capability_case != 0))
			fail("Retained permitted capabilities lost their risk flag");
		if (capability_case == 2 &&
		    capng_have_capability(CAPNG_AMBIENT, CAP_CHOWN)) {
			if (!p.ambient_present || !p.ambient_caps ||
			    strcmp(p.ambient_caps, "chown"))
				fail("Incorrect ambient capability list");
		} else if (p.ambient_present || p.ambient_caps)
			fail("Capability summary invented ambient bits");
		if (p.open_ended_bounding)
			fail("Capability summary invented bounding bits");
		free(p.ambient_caps);
		free(p.caps);
	}
}

static FILE *capture_output(int *saved)
{
	FILE *file = tmpfile();

	*saved = dup(STDOUT_FILENO);
	if (!file || *saved < 0 || fflush(stdout) ||
	    dup2(fileno(file), STDOUT_FILENO) < 0)
		fail("Cannot capture report");
	return file;
}

static char *finish_output(FILE *file, int saved)
{
	long len;
	char *text;

	if (fflush(stdout) || dup2(saved, STDOUT_FILENO) < 0)
		fail("Cannot restore stdout");
	close(saved);
	len = ftell(file);
	if (len < 0 || !(text = calloc((size_t)len + 1, 1)))
		fail("Cannot allocate captured report");
	rewind(file);
	if (fread(text, 1, (size_t)len, file) != (size_t)len)
		fail("Cannot read captured report");
	fclose(file);
	return text;
}

static void expect_json_string(const char *input, const char *expected)
{
	FILE *file;
	char *text;
	int saved;

	file = capture_output(&saved);
	json_escape(input);
	text = finish_output(file, saved);
	if (strcmp(text, expected))
		fail("JSON string encoding changed unexpectedly");
	free(text);
}

static void test_json_string_encoding(void)
{
	expect_json_string("valid-\303\233", "\"valid-\\u00db\"");
	expect_json_string("\303\251", "\"\\u00e9\"");
	expect_json_string("\342\202\254", "\"\\u20ac\"");
	expect_json_string("\360\237\230\200", "\"\\ud83d\\ude00\"");
	expect_json_string("\302\233", "\"\\u009b\"");
	expect_json_string("invalid-\377", "\"invalid-\\u00ff\"");
	expect_json_string("overlong-\300\257",
			   "\"overlong-\\u00c0\\u00af\"");
	expect_json_string("truncated-\342\202",
			   "\"truncated-\\u00e2\\u0082\"");
}

static void test_process_rendering(void)
{
	struct process_info p = {
		.pid = 1234, .comm = "owner", .caps = "(full)",
		.has_privileged_caps = 1,
		.defenses = { "no", "yes", "filter", "unconfined_t" },
	};
	struct endpoint e = { .wildcard_bind = 1, .reuseport = 1 };
	const struct {
		enum plane_kind plane;
		unsigned int port, flags;
		const char *json;
	} cases[] = {
		{ PLANE_INET_EXTERNAL, 80,
		  FLAG_WILDCARD_BIND | FLAG_REUSEPORT | FLAG_PRIVILEGED_CAPS,
		  "[\"wildcard-bind\", \"reuseport\", \"privileged-caps\"]" },
		{ PLANE_BLUETOOTH, 0, FLAG_PROXIMITY_PLANE | FLAG_WILDCARD_BIND |
		  FLAG_REUSEPORT | FLAG_PRIVILEGED_CAPS,
		  "[\"proximity-plane\", \"wildcard-bind\", \"reuseport\", \"privileged-caps\"]" },
		{ PLANE_VSOCK, 22, FLAG_HYPERVISOR_PLANE | FLAG_SSH_VSOCK_22 |
		  FLAG_PRIVILEGED_CAPS,
		  "[\"hypervisor-plane\", \"ssh-on-vsock-port-22\", \"privileged-caps\"]" },
		{ PLANE_VSOCK, 80, FLAG_HYPERVISOR_PLANE | FLAG_PRIVILEGED_CAPS,
		  "[\"hypervisor-plane\", \"privileged-caps\"]" },
	};
	size_t i;
	int saved;
	FILE *file;
	char *text;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		e.plane = cases[i].plane;
		e.port = cases[i].port;
		if (process_flags(&p, &e) != cases[i].flags)
			fail("Process flag selection changed");
		file = capture_output(&saved);
		render_json_process(&p, &e, "");
		text = finish_output(file, saved);
		if (!strstr(text, cases[i].json) || strchr(text, '\033'))
			fail("JSON flag names/order changed");
		free(text);
	}
	use_color = 1;
	file = capture_output(&saved);
	render_tree_process_details("", 1, &p, &e, 80);
	text = finish_output(file, saved);
	if (!strstr(text, "runs_as_nonroot: " COLOR_YELLOW "no" COLOR_RESET) ||
	    !strstr(text, "no_new_privs: " COLOR_GREEN "yes" COLOR_RESET) ||
	    !strstr(text, "seccomp: " COLOR_GREEN "filter" COLOR_RESET) ||
	    !strstr(text, "lsm: " COLOR_ORANGE "unconfined_t" COLOR_RESET))
		fail("Defense colors changed");
	free(text);
	if (strcmp(defense_color("unknown"), "") ||
	    strcmp(defense_color("strict"), COLOR_GREEN) ||
	    strcmp(defense_color("disabled"), COLOR_YELLOW))
		fail("Defense state classification changed");
	use_color = 0;
}

static void test_unknown_posture(void)
{
	struct process_info p = {
		.pid = getpid(), .uid = 1000, .euid = 0, .seen_euid = 1,
		.comm = "unreadable",
	};
	struct proc_status status = {
		.uid = 1000, .euid = 0, .seen_uid = 1, .seen_euid = 1,
	};
	struct endpoint endpoint = { 0 };
	struct model m = { .process_read_failures = 1, .fd_read_failures = 2 };
	char *text;
	FILE *capture;
	int saved, mode;

	capability_case = 4;
	collect_process_caps(&p);
	parse_status_defenses(-1, &p.defenses, &status);
	if (!p.caps_unknown || strcmp(p.caps, "(unknown)") ||
	    strcmp(p.defenses.runs_as_nonroot, "no") ||
	    strcmp(p.defenses.seccomp, "unknown") ||
	    !(process_flags(&p, &endpoint) & FLAG_CAPS_UNKNOWN))
		fail("Unreadable posture was classified as unprivileged");
	capture = capture_output(&saved);
	render_json_process(&p, &endpoint, "");
	text = finish_output(capture, saved);
	if (!strstr(text, "\"caps_known\": false") ||
	    !strstr(text, "\"ambient_present\": null") ||
	    !strstr(text, "\"open_ended_bounding\": null") ||
	    !strstr(text, "\"uid\": 1000, \"euid\": 0") ||
	    !strstr(text, "capabilities-unknown"))
		fail("JSON lost unknown capability or effective identity state");
	free(text);
	use_color = 1;
	capture = capture_output(&saved);
	render_tree_process_details("", 1, &p, &endpoint, 120);
	text = finish_output(capture, saved);
	if (!strstr(text, "caps: (unknown)") ||
	    strstr(text, "caps: " COLOR_GREEN) ||
	    !strstr(text, "capabilities-unknown"))
		fail("Tree displayed unreadable capabilities as safe");
	free(text);
	use_color = 0;
	free(p.caps);
	free(p.defenses.lsm_label);
	status.uid = 0;
	status.euid = 1000;
	parse_status_defenses(-1, &p.defenses, &status);
	if (strcmp(p.defenses.runs_as_nonroot, "yes"))
		fail("Effective non-root identity was hidden by real UID");
	free(p.defenses.lsm_label);
	status.seen_euid = 0;
	for (mode = -1; mode <= 3; mode++) {
		struct defense_info d = { 0 };
		const char *expected[] = { "unknown", "disabled", "strict",
					   "filter", "unknown" };

		status.seen_seccomp = mode >= 0;
		status.seccomp = mode;
		parse_status_defenses(-1, &d, &status);
		if (strcmp(d.seccomp, expected[mode + 1]) ||
		    strcmp(d.runs_as_nonroot, "unknown"))
			fail("Missing or unfamiliar defense metadata was misclassified");
		free(d.lsm_label);
	}
	parse_inet_file(&m, "/missing-netcap-test-table", "tcp", AF_INET);
	capture = capture_output(&saved);
	render_tree(&m);
	text = finish_output(capture, saved);
	if (!strstr(text, "Inspection incomplete: process=1 fd=2") ||
	    !strstr(text, "socket_table=1"))
		fail("Text omitted inventory inspection failures");
	free(text);
	capture = capture_output(&saved);
	render_json(&m);
	text = finish_output(capture, saved);
	if (!strstr(text, "\"inspection_failures\"") ||
	    !strstr(text, "\"process\": 1") ||
	    !strstr(text, "\"socket_table\": 1"))
		fail("JSON omitted inventory inspection failures");
	free(text);
	capability_case = 0;
}

static void test_tree_groups(void)
{
	struct model m = { 0 };
	struct process_info p = {
		.pid = 1234, .comm = "owner", .caps = "(none)",
		.defenses = { "yes", "unknown", "disabled", NULL },
	};
	struct process_info q = p;
	struct process_info *owners[] = { &p, &q };
	struct inode_proc ip = { .procs = owners, .n = 1 };
	struct endpoint_attrs attrs = { 1, 0 };
	FILE *file;
	char *text, *first, *second;
	int saved;

	if (add_endpoint(&m, "tcp", "0.0.0.0", 80, PLANE_INET_EXTERNAL,
			 "eth0", "192.0.2.1", &attrs, &ip) ||
	    add_endpoint(&m, "tcp", "0.0.0.0", 80, PLANE_INET_EXTERNAL,
			 "eth0", "192.0.2.2", &attrs, &ip) ||
	    add_endpoint(&m, "udp6", "::1", 53, PLANE_INET_LOOPBACK,
			 "lo", "::1", &attrs, &ip))
		fail("Cannot build endpoint fixture");
	file = capture_output(&saved);
	render_tree(&m);
	text = finish_output(file, saved);
	first = strstr(text, "owner (pid=1234");
	second = first ? strstr(first + 1, "owner (pid=1234") : NULL;
	if (!first || !second || strstr(second + 1, "owner (pid=1234") ||
	    strstr(text, "├─ owner") ||
	    !strstr(text, "├─ INET (external)") ||
	    !strstr(text, "└─ INET (loopback)") ||
	    !strstr(text, "└─ [::1]") || !strstr(text, "└─ *"))
		fail("Tree grouping, bind formatting, or owner dedup changed");
	free(text);

	/* The physical last endpoint repeats p, but q is the last unique row. */
	q.pid = 5678;
	q.comm = "other";
	ip.n = 2;
	if (add_endpoint(&m, "tcp", "0.0.0.0", 80, PLANE_INET_EXTERNAL,
			 "eth0", "192.0.2.1", &attrs, &ip))
		fail("Cannot add second owner");
	file = capture_output(&saved);
	render_tree(&m);
	text = finish_output(file, saved);
	if (!strstr(text, "├─ owner") || !strstr(text, "└─ other") ||
	    strstr(text, "├─ other"))
		fail("Last unique owner must close the process branch");
	free(text);
	free_model(&m);
}

static void test_inet6_proc_reports(void)
{
	char path[] = "/tmp/netcap-inet6-XXXXXX";
	char proc_addr[33];
	struct in6_addr addr;
	uint32_t words[4];
	struct model m = { 0 };
	struct process_info owner = {
		.pid = 1234, .uid = 1000, .comm = "owner", .caps = "(none)",
		.defenses = { "yes", "no", "disabled", NULL },
	};
	struct endpoint *e;
	FILE *file;
	char *text;
	int fd, saved;

	if (inet_pton(AF_INET6, "::1", &addr) != 1)
		fail("Cannot build IPv6 address fixture");
	/* Match procfs, which prints the address as four native-endian u32s. */
	memcpy(words, &addr, sizeof(words));
	snprintf(proc_addr, sizeof(proc_addr), "%08X%08X%08X%08X",
		 words[0], words[1], words[2], words[3]);
	fd = mkstemp(path);
	if (fd < 0 || !(file = fdopen(fd, "w")))
		fail("Cannot create inet6 table fixture");
	fprintf(file, "header\n"
		"0: %s:AD4D 00000000000000000000000000000000:0000 "
		"0A 00000000:00000000 00:00000000 00000000 1000 0 4242\n",
		proc_addr);
	if (fclose(file))
		fail("Cannot write inet6 table fixture");
	if (add_inode_proc(&m, 4242, &owner))
		fail("Cannot create inet6 socket ownership fixture");
	parse_inet_file(&m, path, "tcp6", AF_INET6);
	unlink(path);

	if (m.eps_n != 1)
		fail("IPv6 procfs endpoint was not parsed");
	e = &m.eps[0];
	if (strcmp(e->bind, "::1") ||
	    strcmp(e->label, "tcp6:[::1]:44365") || e->port != 44365 ||
	    e->plane != PLANE_INET_LOOPBACK || strcmp(e->ifname, "lo"))
		fail("IPv6 procfs endpoint identity changed");

	file = capture_output(&saved);
	render_tree(&m);
	text = finish_output(file, saved);
	if (!strstr(text, "INET (loopback)") || !strstr(text, "[::1]") ||
	    !strstr(text, "44365") || strstr(text, "::1.0.0.0"))
		fail("Tree report changed the IPv6 endpoint");
	free(text);

	file = capture_output(&saved);
	render_json(&m);
	text = finish_output(file, saved);
	if (!strstr(text, "\"addr\": \"::1\"") ||
	    !strstr(text, "\"label\": \"tcp6:[::1]:44365\"") ||
	    !strstr(text, "\"bind\": \"::1\"") ||
	    !strstr(text, "\"port\": 44365") || strstr(text, "::1.0.0.0"))
		fail("JSON report changed the IPv6 endpoint");
	free(text);
	free_model(&m);
}

#ifdef HAVE_NETCAP_VSOCK
static void test_vsock_owners(void)
{
	struct model m = { 0 };
	struct process_info first = { .pid = 100 }, second = { .pid = 200 };
	struct process_info *owners[] = { &first, &second, &first };
	struct inode_proc ip = { .procs = owners, .n = 3 };
	struct endpoint *e;

	if (add_vsock_endpoint(&m, "stream", VMADDR_CID_ANY, 22, &ip) ||
	    add_vsock_endpoint(&m, "stream", VMADDR_CID_ANY, 22, &ip))
		fail("Cannot build VSOCK fixture");
	e = &m.eps[0];
	if (m.eps_n != 1 || e->procs_n != 2 || e->procs[0] != &first ||
	    e->procs[1] != &second || e->plane != PLANE_VSOCK ||
	    e->vsock_cid != VMADDR_CID_ANY || e->port != 22 ||
	    strcmp(e->label, "stream:cid=ANY:22"))
		fail("VSOCK identity or owner merging changed");
	free_model(&m);
}
#endif

#ifdef HAVE_NETCAP_BLUETOOTH
static void test_bluetooth_tables(void)
{
	char path[] = "/tmp/netcap-bluetooth-XXXXXX";
	int fd = mkstemp(path);
	FILE *file;
	struct process_info owner = { .pid = 1234 };
	size_t count, i;

	if (fd < 0 || !(file = fdopen(fd, "w")))
		fail("Cannot create Bluetooth table fixture");
	fputs("sk RefCnt Rmem Wmem User Inode Parent\n"
	      "malformed\n"
	      "0 1 0 0 1000 12 0\n"
	      "0 1 0 0 1000 13 0\n", file);
	if (fclose(file))
		fail("Cannot write Bluetooth table fixture");

	/* Keep this independent of sysfs, Bluetooth hardware, and privileges. */
	bt_adapters_loaded = 1;
	strcpy(bt_adapters[0].name, "hci7");
	strcpy(bt_adapters[0].addr, "AA:BB:CC:DD:EE:FF");
	for (count = 0; count <= 2; count++) {
		struct model m = { 0 };
		const char *name = count == 1 ? "hci7" : "hci?";
		const char *addr = count == 1 ? "AA:BB:CC:DD:EE:FF" : "*";

		bt_adapters_n = count;
		if (add_inode_proc(&m, 12, &owner))
			fail("Cannot create socket ownership fixture");
		parse_bluetooth_file(&m, path, "rfcomm");
		parse_bluetooth_file(&m, path, "hci");
		parse_bluetooth_file(&m, path, "hci");
		if (m.eps_n != 2 || strcmp(m.eps[0].proto, "rfcomm") ||
		    strcmp(m.eps[1].proto, "hci"))
			fail("Bluetooth protocols were lost or duplicated");
		for (i = 0; i < m.eps_n; i++) {
			struct endpoint *e = &m.eps[i];

			if (e->plane != PLANE_BLUETOOTH || e->port != 0 ||
			    strcmp(e->ifname, name) || strcmp(e->bind, addr) ||
			    strcmp(e->ifaddr, addr) || e->procs_n != 1 ||
			    e->procs[0] != &owner)
				fail("Bluetooth ownership or adapter fallback changed");
		}
		free_model(&m);
	}
	unlink(path);
}
#endif

/* Write @contents to a new temporary file and return its path in @path. */
static void write_fixture(char *path, const char *contents)
{
	int fd = mkstemp(path);
	FILE *file;

	if (fd < 0 || !(file = fdopen(fd, "w")))
		fail("Cannot create socket table fixture");
	fputs(contents, file);
	if (fclose(file))
		fail("Cannot write socket table fixture");
}

/*
 * send_nlmsg - queue one netlink message for a parser to receive.
 * @fd: sending end of a datagram socket pair.
 * @type: netlink message type.
 * @flags: netlink header flags.
 * @payload: message body, or NULL.
 * @len: body length in bytes.
 *
 * Each call is one datagram, as the kernel delivers each dump batch.
 */
static void send_nlmsg(int fd, int type, int flags, const void *payload,
		       size_t len)
{
	char buf[NLMSG_SPACE(512)];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	if (NLMSG_SPACE(len) > sizeof(buf))
		fail("Netlink fixture is too large");
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	if (len)
		memcpy(NLMSG_DATA(nlh), payload, len);
	if (send(fd, buf, NLMSG_SPACE(len), 0) < 0)
		fail("Cannot send netlink fixture");
}

static void open_nl_pair(int fds[2])
{
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds))
		fail("Cannot create netlink fixture socket pair");
}

/* Packet sockets report the ethertype as the port, on a named interface. */
static void test_packet_table(void)
{
	char path[] = "/tmp/netcap-packet-XXXXXX";
	char contents[512];
	struct process_info owner = { .pid = 1234 };
	struct model m = { 0 };
	unsigned int lo = if_nametoindex("lo");

	if (!lo)
		fail("Loopback interface index is unavailable");
	snprintf(contents, sizeof(contents),
		 "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n"
		 "malformed\n"
		 "0000000000000000 3 3 0003 %u 1 0 0 5001\n"
		 "0000000000000000 3 3 0003 %u 1 0 0 5999\n"
		 "0000000000000000 3 3 0003 0 1 0 0 5001\n", lo, lo);
	write_fixture(path, contents);
	if (add_inode_proc(&m, 5001, &owner))
		fail("Cannot create packet ownership fixture");
	parse_packet_file(&m, path);
	unlink(path);
	if (m.eps_n != 2 || m.socket_read_failures)
		fail("Packet table rows were not filtered by ownership");
	if (m.eps[0].plane != PLANE_PACKET || strcmp(m.eps[0].proto, "packet") ||
	    m.eps[0].port != 3 || strcmp(m.eps[0].ifname, "lo") ||
	    m.eps[0].wildcard_bind ||
	    m.eps[0].procs_n != 1 || m.eps[0].procs[0] != &owner)
		fail("Packet endpoint identity changed");
	/* Index 0 is bound to no interface, so it sees every interface. */
	if (strcmp(m.eps[1].ifname, "*") || strcmp(m.eps[1].bind, "*") ||
	    !m.eps[1].wildcard_bind)
		fail("All-interface packet socket was not reported as wildcard");
	free_model(&m);
	memset(&m, 0, sizeof(m));

	parse_packet_file(&m, "/nonexistent/netcap-packet");
	if (m.socket_read_failures != 1)
		fail("Unreadable packet table was not counted");
	free_model(&m);
	memset(&m, 0, sizeof(m));
}

#ifdef HAVE_NETCAP_BLUETOOTH
/* Every Bluetooth protocol the kernel publishes must be inventoried. */
static void test_bluetooth_sources(void)
{
	static const char *const required[] = { "l2cap", "rfcomm", "sco", "hci" };
	size_t i, j;

	for (i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
		for (j = 0; j < sizeof(bt_tables) / sizeof(bt_tables[0]); j++) {
			char path[64];

			snprintf(path, sizeof(path), "/proc/net/%s", required[i]);
			if (!strcmp(bt_tables[j].proto, required[i]) &&
			    !strcmp(bt_tables[j].path, path))
				break;
		}
		if (j == sizeof(bt_tables) / sizeof(bt_tables[0]))
			fail("A Bluetooth socket table is not collected");
	}
}

static void test_bluetooth_helpers(void)
{
	bdaddr_t addr = { { 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 } };
	char text[32];
	int id = -1;

	if (bt_parse_adapter_dev_id("hci0", &id) || id != 0 ||
	    bt_parse_adapter_dev_id("hci12", &id) || id != 12)
		fail("HCI adapter names were not parsed");
	if (!bt_parse_adapter_dev_id("hci0x", &id) ||
	    !bt_parse_adapter_dev_id("hcix", &id) ||
	    !bt_parse_adapter_dev_id("hci65536", &id) ||
	    !bt_parse_adapter_dev_id("rfkill0", &id))
		fail("Invalid HCI adapter names were accepted");
	bt_format_addr(&addr, text, sizeof(text));
	if (strcmp(text, "11:22:33:44:55:66"))
		fail("Bluetooth address byte order changed");
	if (!str_is_bdaddr("11:22:33:44:55:66") ||
	    str_is_bdaddr("11:22:33:44:55") || str_is_bdaddr("11-22-33-44-55-66") ||
	    str_is_bdaddr("11:22:33:44:55:6G") || str_is_bdaddr(NULL))
		fail("Bluetooth address validation changed");
}
#endif

#ifdef HAVE_NETCAP_VSOCK
static void test_vsock_table(void)
{
	char path[] = "/tmp/netcap-vsock-XXXXXX";
	struct process_info owner = { .pid = 1234 };
	struct model m = { 0 };
	unsigned int v;

	if (parse_u32_hex_or_dec("1024", &v) || v != 1024 ||
	    parse_u32_hex_or_dec("0x1F", &v) || v != 31 ||
	    parse_u32_hex_or_dec("0A", &v) || v != 10 ||
	    !parse_u32_hex_or_dec("", &v) || !parse_u32_hex_or_dec("12z", &v) ||
	    !parse_u32_hex_or_dec("0x100000000", &v))
		fail("VSOCK numeric tokens were misparsed");

	write_fixture(path, "Num Local Remote Type St Inode\n"
		      "0 3:1024 0:0 1 0A 6001\n"
		      "0 3:1025 0:0 1 01 6001\n"
		      "0 3:2048 0:0 2 07 6001\n"
		      "0 3:0 0:0 2 07 6001\n"
		      "0 3:4096 0:0 1 0A 6999\n");
	if (add_inode_proc(&m, 6001, &owner))
		fail("Cannot create VSOCK ownership fixture");
	parse_vsock_file(&m, path);
	unlink(path);
	/* A listening stream and a bound datagram socket; others are skipped. */
	if (m.eps_n != 2 || strcmp(m.eps[0].label, "stream:cid=3:1024") ||
	    strcmp(m.eps[1].label, "dgram:cid=3:2048") ||
	    m.eps[0].plane != PLANE_VSOCK)
		fail("VSOCK procfs listeners changed");
	free_model(&m);
	memset(&m, 0, sizeof(m));
}

#ifdef HAVE_LINUX_VM_SOCKETS_DIAG_H
static void test_vsock_diag_messages(void)
{
	struct process_info owner = { .pid = 1234 };
	struct vsock_diag_msg r = { 0 };
	struct nlmsgerr err = { 0 };
	struct model m = { 0 };
	int fds[2];

	open_nl_pair(fds);
	r.vdiag_family = AF_VSOCK;
	r.vdiag_type = SOCK_STREAM;
	r.vdiag_state = TCP_LISTEN;
	r.vdiag_src_cid = 2;
	r.vdiag_src_port = 22;
	r.vdiag_ino = 7001;
	send_nlmsg(fds[1], SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, &r, sizeof(r));
	r.vdiag_state = TCP_ESTABLISHED;
	r.vdiag_src_port = 23;
	send_nlmsg(fds[1], SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, &r, sizeof(r));
	send_nlmsg(fds[1], NLMSG_DONE, NLM_F_MULTI, NULL, 0);
	if (add_inode_proc(&m, 7001, &owner))
		fail("Cannot create VSOCK diag ownership fixture");
	if (parse_vsock_diag_messages(&m, fds[0]) != 0 || m.eps_n != 1 ||
	    strcmp(m.eps[0].label, "stream:cid=2:22"))
		fail("VSOCK diag listener was not parsed");
	free_model(&m);
	memset(&m, 0, sizeof(m));

	err.error = -EPERM;
	send_nlmsg(fds[1], NLMSG_ERROR, 0, &err, sizeof(err));
	errno = 0;
	if (parse_vsock_diag_messages(&m, fds[0]) != -1 || errno != EPERM)
		fail("VSOCK diag error reply was not reported");
	free_model(&m);
	memset(&m, 0, sizeof(m));
	close(fds[0]);
	close(fds[1]);
}
#endif
#endif

static void test_inet_diag_messages(void)
{
	struct process_info owner = { .pid = 1234 };
	struct inet_diag_msg r = { 0 };
	struct model m = { 0 };
	int fds[2];

	open_nl_pair(fds);
	r.idiag_family = AF_INET;
	r.idiag_state = TCP_LISTEN;
	r.id.idiag_sport = htons(5000);
	r.id.idiag_src[0] = htonl(INADDR_LOOPBACK);
	r.idiag_inode = 8001;
	send_nlmsg(fds[1], SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, &r, sizeof(r));
	r.idiag_inode = 8999;
	send_nlmsg(fds[1], SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, &r, sizeof(r));
	send_nlmsg(fds[1], NLMSG_DONE, NLM_F_MULTI, NULL, 0);
	if (add_inode_proc(&m, 8001, &owner))
		fail("Cannot create inet diag ownership fixture");
	if (parse_diag_messages(&m, fds[0], IPPROTO_SCTP, AF_INET) != 0 ||
	    m.eps_n != 1 || strcmp(m.eps[0].proto, "sctp") ||
	    m.eps[0].port != 5000 || strcmp(m.eps[0].bind, "127.0.0.1"))
		fail("SCTP diag listener was not parsed");
	free_model(&m);
	memset(&m, 0, sizeof(m));
	close(fds[0]);
	close(fds[1]);
}

static void render_text_report(char *name)
{
	struct model m = { 0 };
	struct process_info p = {
		.pid = 1234, .uid = 1000, .comm = name,
		.caps = "(none)",
		.defenses = { "yes", "no", "disabled", NULL },
	};
	struct process_info *owners[] = { &p };
	struct inode_proc ip = { .procs = owners, .n = 1 };
	struct endpoint_attrs attrs = { 1, 0 };

	if (add_endpoint(&m, "tcp", "0.0.0.0", 80,
			 PLANE_INET_EXTERNAL, "eth0", "192.0.2.1",
			 &attrs, &ip))
		fail("Cannot build process text JSON fixture");
	render_json(&m);
	free_model(&m);
}

/* Exercise collection as well as encoding: an encoder-only test cannot catch
 * terminal sanitization destroying Unicode before JSON serialization.
 */
static void render_collected_report(const char *name)
{
	struct model m = { 0 };
	struct process_info *p;
	struct endpoint e = { 0 };
	FILE *file;
	char *text, *safe;
	const char *cursor;
	int saved, i;

	if (prctl(PR_SET_NAME, name, 0, 0, 0))
		fail("Cannot set process-name fixture");
	p = add_process(&m, getpid());
	if (!p || strcmp(p->comm, name))
		fail("Collection changed the process name");

	/* Supply deterministic values for host-dependent metadata, exercising
	 * the same terminal/JSON separation for every untrusted process field.
	 */
	free(p->exe);
	free(p->unit);
	free(p->defenses.lsm_label);
	p->exe = xstrdup(name);
	p->unit = xstrdup(name);
	p->defenses.lsm_label = xstrdup(name);
	safe = sanitize_untrusted_field(name);
	if (!p->exe || !p->unit || !p->defenses.lsm_label || !safe)
		fail("Cannot allocate process text fixture");
	use_color = 0;
	file = capture_output(&saved);
	render_tree_process_details("", 1, p, &e, 4096);
	text = finish_output(file, saved);
	cursor = text;
	for (i = 0; i < 4; i++) {
		cursor = strstr(cursor, safe);
		if (!cursor)
			fail("Terminal process field was not sanitized");
		cursor += strlen(safe);
	}
	if (strchr(text, '\033') || strchr(text, '\233'))
		fail("Terminal output contains a process control byte");
	free(text);
	free(safe);
	/* Rendering the tree first must not alter subsequent JSON output. */
	render_json_process(p, &e, "");
	free_model(&m);
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--invalid-utf8-json")) {
		render_text_report("invalid-\377");
		return EXIT_SUCCESS;
	}
	if (argc == 3 && !strcmp(argv[1], "--process-json")) {
		render_collected_report(argv[2]);
		return EXIT_SUCCESS;
	}
	if (argc == 3 && !strcmp(argv[1], "--text-json")) {
		render_text_report(argv[2]);
		return EXIT_SUCCESS;
	}
	if (argc != 1)
		fail("Unexpected netcap test argument");

	test_permitted_summary();
	test_newer_kernel_capability();
	test_json_string_encoding();
	test_process_rendering();
	test_unknown_posture();
	test_tree_groups();
	test_inet6_proc_reports();
#ifdef HAVE_NETCAP_VSOCK
	test_vsock_owners();
#endif
#ifdef HAVE_NETCAP_BLUETOOTH
	test_bluetooth_tables();
	test_bluetooth_helpers();
	test_bluetooth_sources();
#endif
	test_packet_table();
#ifdef HAVE_NETCAP_VSOCK
	test_vsock_table();
#ifdef HAVE_LINUX_VM_SOCKETS_DIAG_H
	test_vsock_diag_messages();
#endif
#endif
	test_inet_diag_messages();
	puts("Advanced netcap tests passed");
	return 0;
}
