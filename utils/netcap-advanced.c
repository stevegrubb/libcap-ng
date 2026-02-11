#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "netcap-advanced.h"

struct defense_kv {
	const char *key;
	const char *value;
};

struct process {
	const char *comm;
	int pid;
	int uid;
	const char *unit;
	const char *caps_summary;
	const struct defense_kv *defenses;
	size_t defenses_count;
	const char **flags;
	size_t flags_count;
};

struct endpoint {
	const char *label;
	const struct process *processes;
	size_t processes_count;
};

struct addr {
	const char *value;
	const struct endpoint *endpoints;
	size_t endpoints_count;
};

struct iface {
	const char *name;
	const struct addr *addrs;
	size_t addrs_count;
};

struct plane {
	const char *name;
	const char *scope;
	const struct iface *ifaces;
	size_t ifaces_count;
	const struct endpoint *endpoints;
	size_t endpoints_count;
};

struct model {
	int schema_version;
	const struct plane *planes;
	size_t planes_count;
};

static int get_width(void)
{
	struct winsize ws;
	const char *env;
	char *end = NULL;
	unsigned long v;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col)
		return ws.ws_col;
	env = getenv("COLUMNS");
	if (env) {
		v = strtoul(env, &end, 10);
		if (end != env && *end == '\0' && v > 0)
			return (int)v;
	}
	return 80;
}

static void print_indent(int depth, const int *bars)
{
	int i;

	for (i = 0; i < depth; i++)
		fputs(bars[i] ? "│  " : "   ", stdout);
}

static int wrap_to(const char *text, int from, int limit)
{
	int i;
	int space = -1;

	for (i = from; text[i] && (i - from) < limit; i++)
		if (text[i] == ' ')
			space = i;
	if (!text[i])
		return i;
	if (space > from)
		return space;
	if (i == from)
		return from + 1;
	return i;
}

static void print_wrapped_with_prefix(int depth, const int *bars,
				      int last, const char *text,
				      int width, int with_branch)
{
	int pos = 0;
	int first = 1;
	int avail;
	int to;

	while (1) {
		print_indent(depth, bars);
		if (with_branch)
			fputs(first ? (last ? "└─ " : "├─ ") : "   ", stdout);
		avail = width - (depth * 3) - (with_branch ? 3 : 0);
		if (avail < 10)
			avail = 10;
		if (!text[pos]) {
			fputc('\n', stdout);
			return;
		}
		to = wrap_to(text, pos, avail);
		printf("%.*s\n", to - pos, text + pos);
		while (text[to] == ' ')
			to++;
		pos = to;
		first = 0;
		if (!text[pos])
			return;
	}
}

static void print_node(int depth, const int *bars, int last, const char *label,
		       int width)
{
	print_wrapped_with_prefix(depth, bars, last, label, width, 1);
}

static void print_root_line(const char *label, int width)
{
	const int bars[1] = { 0 };

	print_wrapped_with_prefix(0, bars, 1, label, width, 0);
}

static void json_indent(int n)
{
	while (n--)
		fputs("  ", stdout);
}

static void json_str(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	fputc('"', stdout);
	for (; *p; p++) {
		switch (*p) {
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		default:
			if (*p < 0x20)
				printf("\\u%04x", *p);
			else
				fputc(*p, stdout);
		}
	}
	fputc('"', stdout);
}

static void print_defenses_json(const struct defense_kv *d, size_t n, int ind)
{
	size_t i;

	fputs("{\n", stdout);
	for (i = 0; i < n; i++) {
		json_indent(ind + 1);
		json_str(d[i].key);
		fputs(": ", stdout);
		json_str(d[i].value);
		if (i + 1 != n)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(ind);
	fputc('}', stdout);
}

static void print_flags_json(const char **flags, size_t n, int ind)
{
	size_t i;

	fputs("[\n", stdout);
	for (i = 0; i < n; i++) {
		json_indent(ind + 1);
		json_str(flags[i]);
		if (i + 1 != n)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(ind);
	fputc(']', stdout);
}

static void print_process_json(const struct process *p, int ind, int last)
{
	json_indent(ind);
	fputs("{\n", stdout);
	json_indent(ind + 1);
	fputs("\"comm\": ", stdout);
	json_str(p->comm);
	fputs(",\n", stdout);
	json_indent(ind + 1);
	fputs("\"pid\": ", stdout);
	printf("%d,\n", p->pid);
	json_indent(ind + 1);
	fputs("\"uid\": ", stdout);
	printf("%d,\n", p->uid);
	if (p->unit) {
		json_indent(ind + 1);
		fputs("\"unit\": ", stdout);
		json_str(p->unit);
		fputs(",\n", stdout);
	}
	json_indent(ind + 1);
	fputs("\"caps\": {\n", stdout);
	json_indent(ind + 2);
	fputs("\"summary\": ", stdout);
	json_str(p->caps_summary);
	fputc('\n', stdout);
	json_indent(ind + 1);
	fputs("},\n", stdout);
	json_indent(ind + 1);
	fputs("\"defenses\": ", stdout);
	print_defenses_json(p->defenses, p->defenses_count, ind + 1);
	fputs(",\n", stdout);
	json_indent(ind + 1);
	fputs("\"flags\": ", stdout);
	print_flags_json(p->flags, p->flags_count, ind + 1);
	fputc('\n', stdout);
	json_indent(ind);
	fputc('}', stdout);
	if (!last)
		fputc(',', stdout);
	fputc('\n', stdout);
}

static void print_endpoints_json(const struct endpoint *e, size_t n, int ind)
{
	size_t i;
	size_t j;

	fputs("[\n", stdout);
	for (i = 0; i < n; i++) {
		json_indent(ind + 1);
		fputs("{\n", stdout);
		json_indent(ind + 2);
		fputs("\"label\": ", stdout);
		json_str(e[i].label);
		fputs(",\n", stdout);
		json_indent(ind + 2);
		fputs("\"processes\": [\n", stdout);
		for (j = 0; j < e[i].processes_count; j++)
			print_process_json(&e[i].processes[j], ind + 3,
					 j + 1 == e[i].processes_count);
		json_indent(ind + 2);
		fputs("]\n", stdout);
		json_indent(ind + 1);
		fputc('}', stdout);
		if (i + 1 != n)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(ind);
	fputc(']', stdout);
}

static void print_addrs_json(const struct addr *a, size_t n, int ind)
{
	size_t i;

	fputs("[\n", stdout);
	for (i = 0; i < n; i++) {
		json_indent(ind + 1);
		fputs("{\n", stdout);
		json_indent(ind + 2);
		fputs("\"addr\": ", stdout);
		json_str(a[i].value);
		fputs(",\n", stdout);
		json_indent(ind + 2);
		fputs("\"endpoints\": ", stdout);
		print_endpoints_json(a[i].endpoints, a[i].endpoints_count, ind + 2);
		fputc('\n', stdout);
		json_indent(ind + 1);
		fputc('}', stdout);
		if (i + 1 != n)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(ind);
	fputc(']', stdout);
}

static void print_ifaces_json(const struct iface *ifc, size_t n, int ind)
{
	size_t i;

	fputs("[\n", stdout);
	for (i = 0; i < n; i++) {
		json_indent(ind + 1);
		fputs("{\n", stdout);
		json_indent(ind + 2);
		fputs("\"name\": ", stdout);
		json_str(ifc[i].name);
		fputs(",\n", stdout);
		json_indent(ind + 2);
		fputs("\"addr\": ", stdout);
		print_addrs_json(ifc[i].addrs, ifc[i].addrs_count, ind + 2);
		fputc('\n', stdout);
		json_indent(ind + 1);
		fputc('}', stdout);
		if (i + 1 != n)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(ind);
	fputc(']', stdout);
}

static void render_json(const struct model *m)
{
	size_t i;

	fputs("{\n", stdout);
	json_indent(1);
	fputs("\"schema_version\": ", stdout);
	printf("%d,\n", m->schema_version);
	json_indent(1);
	fputs("\"planes\": [\n", stdout);
	for (i = 0; i < m->planes_count; i++) {
		json_indent(2);
		fputs("{\n", stdout);
		json_indent(3);
		fputs("\"name\": ", stdout);
		json_str(m->planes[i].name);
		if (m->planes[i].scope) {
			fputs(",\n", stdout);
			json_indent(3);
			fputs("\"scope\": ", stdout);
			json_str(m->planes[i].scope);
		}
		if (m->planes[i].ifaces_count) {
			fputs(",\n", stdout);
			json_indent(3);
			fputs("\"interfaces\": ", stdout);
			print_ifaces_json(m->planes[i].ifaces,
					m->planes[i].ifaces_count, 3);
			fputc('\n', stdout);
		} else {
			fputs(",\n", stdout);
			json_indent(3);
			fputs("\"endpoints\": ", stdout);
			print_endpoints_json(m->planes[i].endpoints,
					     m->planes[i].endpoints_count,
					     3);
			fputc('\n', stdout);
		}
		json_indent(2);
		fputc('}', stdout);
		if (i + 1 != m->planes_count)
			fputc(',', stdout);
		fputc('\n', stdout);
	}
	json_indent(1);
	fputs("]\n", stdout);
	fputs("}\n", stdout);
}

static void render_process_tree(const struct process *p, int depth, int *bars,
				int last, int width)
{
	char label[768];
	size_t i;

	if (p->unit)
		snprintf(label, sizeof(label), "%s (pid=%d uid=%d unit=%s)",
			 p->comm, p->pid, p->uid, p->unit);
	else
		snprintf(label, sizeof(label), "%s (pid=%d uid=%d)",
			 p->comm, p->pid, p->uid);
	print_node(depth, bars, last, label, width);
	bars[depth] = !last;

	snprintf(label, sizeof(label), "caps: %s", p->caps_summary);
	print_node(depth + 1, bars, 0, label, width);
	print_node(depth + 1, bars, 0, "defenses", width);
	bars[depth + 1] = 1;
	for (i = 0; i < p->defenses_count; i++) {
		snprintf(label, sizeof(label), "%s: %s",
			 p->defenses[i].key, p->defenses[i].value);
		print_node(depth + 2, bars, i + 1 == p->defenses_count,
			   label, width);
	}
	print_node(depth + 1, bars, 1, "flags", width);
	bars[depth + 1] = 0;
	for (i = 0; i < p->flags_count; i++)
		print_node(depth + 2, bars, i + 1 == p->flags_count,
			   p->flags[i], width);
}

static void render_endpoint_tree(const struct endpoint *e, int depth, int *bars,
				 int last, int width)
{
	size_t i;

	print_node(depth, bars, last, e->label, width);
	bars[depth] = !last;
	for (i = 0; i < e->processes_count; i++)
		render_process_tree(&e->processes[i], depth + 1, bars,
				    i + 1 == e->processes_count, width);
}

static void render_addr_tree(const struct addr *a, int depth, int *bars,
			     int last, int width)
{
	size_t i;
	char label[256];

	snprintf(label, sizeof(label), "addr: %s", a->value);
	print_node(depth, bars, last, label, width);
	bars[depth] = !last;
	for (i = 0; i < a->endpoints_count; i++)
		render_endpoint_tree(&a->endpoints[i], depth + 1, bars,
				     i + 1 == a->endpoints_count, width);
}

static void render_iface_tree(const struct iface *ifc, int depth, int *bars,
			      int last, int width)
{
	size_t i;

	print_node(depth, bars, last, ifc->name, width);
	bars[depth] = !last;
	for (i = 0; i < ifc->addrs_count; i++)
		render_addr_tree(&ifc->addrs[i], depth + 1, bars,
				 i + 1 == ifc->addrs_count, width);
}

static void render_plane_tree(const struct plane *p, int depth, int *bars,
			      int last, int width)
{
	size_t i;
	char label[128];

	if (p->scope)
		snprintf(label, sizeof(label), "%s (%s)", p->name, p->scope);
	else
		snprintf(label, sizeof(label), "%s", p->name);
	print_node(depth, bars, last, label, width);
	bars[depth] = !last;
	if (p->ifaces_count) {
		for (i = 0; i < p->ifaces_count; i++)
			render_iface_tree(&p->ifaces[i], depth + 1, bars,
				  i + 1 == p->ifaces_count, width);
	} else {
		for (i = 0; i < p->endpoints_count; i++)
			render_endpoint_tree(&p->endpoints[i], depth + 1, bars,
				     i + 1 == p->endpoints_count, width);
	}
}

static void render_tree(const struct model *m)
{
	int bars[16] = { 0 };
	size_t i;
	int width = get_width();

	print_root_line("netcap --advanced", width);
	bars[0] = 0;
	for (i = 0; i < m->planes_count; i++)
		render_plane_tree(&m->planes[i], 0, bars,
				  i + 1 == m->planes_count, width);
}

static const struct model *sample_model(void)
{
	static const struct defense_kv d_external[] = {
		{ "runs_as_root", "no" },
		{ "seccomp", "filter" },
		{ "no_new_privs", "yes" },
	};
	static const struct defense_kv d_loopback[] = {
		{ "runs_as_root", "no" },
		{ "seccomp", "strict" },
		{ "no_new_privs", "yes" },
	};
	static const struct defense_kv d_vsock[] = {
		{ "runs_as_root", "yes" },
		{ "seccomp", "disabled" },
		{ "no_new_privs", "no" },
	};
	static const char *f_external[] = {
		"wildcard-bind",
	};
	static const char *f_loopback[] = {
		"loopback-only",
	};
	static const char *f_vsock[] = {
		"hypervisor-plane",
	};
	static const char *f_ll[] = {
		"link-layer-capture",
	};
	static const struct process p_external[] = {
		{
			.comm = "sampled",
			.pid = 1234,
			.uid = 1001,
			.unit = NULL,
			.caps_summary = "cap_net_bind_service, cap_net_admin, "
				       "cap_net_raw [ambient-present] "
				       "[open-ended-bounding]",
			.defenses = d_external,
			.defenses_count = sizeof(d_external) / sizeof(d_external[0]),
			.flags = f_external,
			.flags_count = sizeof(f_external) / sizeof(f_external[0]),
		},
	};
	static const struct process p_loopback[] = {
		{
			.comm = "loopd",
			.pid = 2234,
			.uid = 1002,
			.unit = NULL,
			.caps_summary = "cap_net_bind_service",
			.defenses = d_loopback,
			.defenses_count = sizeof(d_loopback) / sizeof(d_loopback[0]),
			.flags = f_loopback,
			.flags_count = sizeof(f_loopback) / sizeof(f_loopback[0]),
		},
	};
	static const struct process p_vsock[] = {
		{
			.comm = "vsockd",
			.pid = 3234,
			.uid = 0,
			.unit = "vm-guest@3.service",
			.caps_summary = "cap_sys_admin, cap_net_admin "
				       "[open-ended-bounding]",
			.defenses = d_vsock,
			.defenses_count = sizeof(d_vsock) / sizeof(d_vsock[0]),
			.flags = f_vsock,
			.flags_count = sizeof(f_vsock) / sizeof(f_vsock[0]),
		},
	};
	static const struct process p_ll[] = {
		{
			.comm = "pktmon",
			.pid = 4234,
			.uid = 0,
			.unit = NULL,
			.caps_summary = "cap_net_raw [ambient-present]",
			.defenses = d_external,
			.defenses_count = sizeof(d_external) / sizeof(d_external[0]),
			.flags = f_ll,
			.flags_count = sizeof(f_ll) / sizeof(f_ll[0]),
		},
	};
	static const struct endpoint e_external[] = {
		{ .label = "tcp:0.0.0.0:443", .processes = p_external,
		  .processes_count = sizeof(p_external) / sizeof(p_external[0]) },
	};
	static const struct endpoint e_loopback[] = {
		{ .label = "tcp:[::1]:8080", .processes = p_loopback,
		  .processes_count = sizeof(p_loopback) / sizeof(p_loopback[0]) },
	};
	static const struct endpoint e_vsock[] = {
		{ .label = "stream:cid=3:1024", .processes = p_vsock,
		  .processes_count = sizeof(p_vsock) / sizeof(p_vsock[0]) },
	};
	static const struct endpoint e_ll[] = {
		{ .label = "packet:02:42:ac:11:00:02:0x0800", .processes = p_ll,
		  .processes_count = sizeof(p_ll) / sizeof(p_ll[0]) },
	};
	static const struct addr a_external[] = {
		{ .value = "0.0.0.0", .endpoints = e_external,
		  .endpoints_count = sizeof(e_external) / sizeof(e_external[0]) },
	};
	static const struct addr a_loopback[] = {
		{ .value = "::1", .endpoints = e_loopback,
		  .endpoints_count = sizeof(e_loopback) / sizeof(e_loopback[0]) },
	};
	static const struct addr a_ll[] = {
		{ .value = "02:42:ac:11:00:02", .endpoints = e_ll,
		  .endpoints_count = sizeof(e_ll) / sizeof(e_ll[0]) },
	};
	static const struct iface i_external[] = {
		{ .name = "eth0", .addrs = a_external,
		  .addrs_count = sizeof(a_external) / sizeof(a_external[0]) },
	};
	static const struct iface i_loopback[] = {
		{ .name = "lo", .addrs = a_loopback,
		  .addrs_count = sizeof(a_loopback) / sizeof(a_loopback[0]) },
	};
	static const struct iface i_ll[] = {
		{ .name = "eth0", .addrs = a_ll,
		  .addrs_count = sizeof(a_ll) / sizeof(a_ll[0]) },
	};
	static const struct plane planes[] = {
		{
			.name = "INET",
			.scope = "external",
			.ifaces = i_external,
			.ifaces_count = sizeof(i_external) / sizeof(i_external[0]),
			.endpoints = NULL,
			.endpoints_count = 0,
		},
		{
			.name = "INET",
			.scope = "loopback",
			.ifaces = i_loopback,
			.ifaces_count = sizeof(i_loopback) / sizeof(i_loopback[0]),
			.endpoints = NULL,
			.endpoints_count = 0,
		},
		{
			.name = "VSOCK",
			.scope = NULL,
			.ifaces = NULL,
			.ifaces_count = 0,
			.endpoints = e_vsock,
			.endpoints_count = sizeof(e_vsock) / sizeof(e_vsock[0]),
		},
		{
			.name = "LINK-LAYER",
			.scope = NULL,
			.ifaces = i_ll,
			.ifaces_count = sizeof(i_ll) / sizeof(i_ll[0]),
			.endpoints = NULL,
			.endpoints_count = 0,
		},
	};
	static const struct model m = {
		.schema_version = 1,
		.planes = planes,
		.planes_count = sizeof(planes) / sizeof(planes[0]),
	};

	return &m;
}

int netcap_advanced_main(const struct netcap_opts *opts)
{
	const struct model *m;

	if (!opts || !opts->advanced)
		return 1;

	m = sample_model();
	if (opts->json)
		render_json(m);
	else
		render_tree(m);

	return 0;
}
