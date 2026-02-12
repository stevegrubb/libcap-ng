#include "config.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/capability.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/vm_sockets.h>
#ifdef HAVE_LINUX_VM_SOCKETS_DIAG_H
#include <linux/vm_sockets_diag.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "cap-ng.h"
#include "netcap-advanced.h"

/*
 * Overview:
 * netcap --advanced builds a process/socket ownership model from procfs and
 * sock_diag, then renders it as a tree or JSON without changing system state.
 *
 * The flow is: discover interface addresses, map socket inode->process
 * ownership from /proc/<pid>/fd, parse protocol-specific listener tables,
 * and project each endpoint onto interface/plane groupings for reporting.
 *
 * For internet sockets, wildcard binds are expanded onto concrete interface
 * addresses so the rendered tree/JSON can be consumed as an exposure map.
 * VSOCK listeners are collected via sock_diag when available and fall back to
 * /proc parsing when not, with ownership stitched back through socket inodes.
 *
 * Results depend on the current network namespace and procfs visibility;
 * restricted privileges can hide processes/sockets and yield partial output.
 */

#define MAX_BARS 64

#ifdef NETCAP_DIAG_DEBUG
#define diag_dbg(fmt, ...) \
	fprintf(stderr, "netcap-diag: " fmt "\n", ##__VA_ARGS__)
#else
#define diag_dbg(fmt, ...) do { } while (0)
#endif

enum plane_kind {
	PLANE_INET_EXTERNAL,
	PLANE_INET_LOOPBACK,
	PLANE_PACKET,
	PLANE_VSOCK,
};

#define PLANE_PACKET_NAME	"LINK-LAYER"

struct strvec {
	char **v;
	size_t n;
	size_t cap;
};

struct iface_addr {
	int af;
	char *addr;
};

struct iface_info {
	char *name;
	struct iface_addr *addrs;
	size_t addrs_n;
	size_t addrs_cap;
};

struct defense_info {
	char *runs_as_nonroot;
	char *no_new_privs;
	char *seccomp;
	char *lsm_label;
	char *securebits;
	char *securebits_locked;
};

struct process_info {
	int pid;
	int uid;
	char *comm;
	char *unit;
	char *caps;
	int has_privileged_caps;
	int securebits_locked;
	struct defense_info defenses;
};

struct inode_proc {
	unsigned long inode;
	struct process_info **procs;
	size_t n;
	size_t cap;
};

struct endpoint {
	char *proto;
	char *bind;
	char *label;
	unsigned int port;
	unsigned int vsock_cid;
	int has_vsock;
	enum plane_kind plane;
	char *ifname;
	char *ifaddr;
	struct process_info **procs;
	size_t procs_n;
	size_t procs_cap;
	int wildcard_bind;
	int loopback_only;
};

struct model {
	struct iface_info *ifaces;
	size_t ifaces_n;
	size_t ifaces_cap;
	struct process_info **procs;
	size_t procs_n;
	size_t procs_cap;
	struct inode_proc *inode_map;
	size_t inode_n;
	size_t inode_cap;
	struct endpoint *eps;
	size_t eps_n;
	size_t eps_cap;
};

static void free_process(struct process_info *p);
static void free_model(struct model *m);

/*
 * get_width - choose terminal width for wrapped tree output.
 *
 * Returns terminal columns from TIOCGWINSZ or $COLUMNS, else 80.
 */
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

/*
 * xstrdup - duplicate @s into a newly allocated string.
 * @s: source string, or NULL.
 *
 * Returns caller-owned copy, or NULL for NULL input or allocation failure.
 */
static char *xstrdup(const char *s)
{
	char *p;

	if (!s)
		return NULL;
	p = strdup(s);
	if (!p)
		fprintf(stderr, "Out of memory\n");
	return p;
}

/*
 * vec_grow - grow vector storage for dynamic arrays.
 * @v: pointer to heap buffer pointer updated on success.
 * @cap: current/new capacity element count.
 * @item: size in bytes of each element.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int vec_grow(void **v, size_t *cap, size_t item)
{
	void *p;
	size_t ncap;

	if (*cap)
		ncap = *cap * 2;
	else
		ncap = 8;
	p = realloc(*v, ncap * item);
	if (!p) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}
	*v = p;
	*cap = ncap;
	return 0;
}

/*
 * push_str_unique - append @s to @sv when not already present.
 * @sv: destination vector that takes ownership of duplicated strings.
 * @s: string to deduplicate and append.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int push_str_unique(struct strvec *sv, const char *s)
{
	size_t i;

	for (i = 0; i < sv->n; i++)
		if (strcmp(sv->v[i], s) == 0)
			return 0;
	if (sv->n == sv->cap && vec_grow((void **)&sv->v, &sv->cap,
		sizeof(char *)))
		return -1;
	sv->v[sv->n++] = xstrdup(s);
	return sv->v[sv->n - 1] ? 0 : -1;
}

/*
 * str_is_loopback - check whether textual @addr is loopback for @af.
 *
 * Returns non-zero for loopback addresses, else 0.
 */
static int str_is_loopback(int af, const char *addr)
{
	struct in_addr a4;
	struct in6_addr a6;

	if (af == AF_INET) {
		if (inet_pton(AF_INET, addr, &a4) != 1)
			return 0;
		return (ntohl(a4.s_addr) & 0xff000000U) == 0x7f000000U;
	}
	if (af == AF_INET6) {
		if (inet_pton(AF_INET6, addr, &a6) != 1)
			return 0;
		return IN6_IS_ADDR_LOOPBACK(&a6);
	}
	return 0;
}

/*
 * str_is_wildcard - check whether textual @addr is wildcard-any for @af.
 *
 * Returns non-zero for 0.0.0.0/:: wildcard binds, else 0.
 */
static int str_is_wildcard(int af, const char *addr)
{
	if (af == AF_INET)
		return strcmp(addr, "0.0.0.0") == 0;
	if (af == AF_INET6)
		return strcmp(addr, "::") == 0;
	return 0;
}

/*
 * find_iface - locate interface record by name in @m.
 *
 * Returns a mutable iface pointer on match, or NULL if not found.
 */
static struct iface_info *find_iface(struct model *m, const char *name)
{
	size_t i;

	for (i = 0; i < m->ifaces_n; i++)
		if (strcmp(m->ifaces[i].name, name) == 0)
			return &m->ifaces[i];
	return NULL;
}

/*
 * add_iface_addr - append one interface address if not already present.
 * @ifc: interface record to update (takes ownership of duplicated @addr).
 * @af: address family for @addr.
 * @addr: textual address to copy into @ifc.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int add_iface_addr(struct iface_info *ifc, int af, const char *addr)
{
	size_t i;

	for (i = 0; i < ifc->addrs_n; i++) {
		if (ifc->addrs[i].af == af && strcmp(ifc->addrs[i].addr, addr) == 0)
			return 0;
	}
	if (ifc->addrs_n == ifc->addrs_cap && vec_grow((void **)&ifc->addrs,
		&ifc->addrs_cap, sizeof(struct iface_addr)))
		return -1;
	ifc->addrs[ifc->addrs_n].af = af;
	ifc->addrs[ifc->addrs_n].addr = xstrdup(addr);
	if (!ifc->addrs[ifc->addrs_n].addr)
		return -1;
	ifc->addrs_n++;
	return 0;
}

/*
 * collect_interfaces - snapshot AF_INET/AF_INET6 iface addresses in @m.
 * @m: model populated from getifaddrs() in the current network namespace.
 *
 * Returns 0 on success, -1 on getifaddrs/allocation failure.
 */
static int collect_interfaces(struct model *m)
{
	struct ifaddrs *ifa, *cur;
	char buf[INET6_ADDRSTRLEN];
	struct iface_info *ifc;

	if (getifaddrs(&ifa) != 0)
		return -1;
	for (cur = ifa; cur; cur = cur->ifa_next) {
		if (!cur->ifa_name || !cur->ifa_addr)
			continue;
		if (cur->ifa_addr->sa_family != AF_INET &&
		    cur->ifa_addr->sa_family != AF_INET6)
			continue;
		ifc = find_iface(m, cur->ifa_name);
		if (!ifc) {
			if (m->ifaces_n == m->ifaces_cap &&
			    vec_grow((void **)&m->ifaces, &m->ifaces_cap,
			    sizeof(struct iface_info)))
				goto fail;
			ifc = &m->ifaces[m->ifaces_n++];
			memset(ifc, 0, sizeof(*ifc));
			ifc->name = xstrdup(cur->ifa_name);
			if (!ifc->name)
				goto fail;
		}
		if (cur->ifa_addr->sa_family == AF_INET) {
			if (!inet_ntop(AF_INET,
				&((struct sockaddr_in *)cur->ifa_addr)->sin_addr,
				buf, sizeof(buf)))
				continue;
		} else {
			if (!inet_ntop(AF_INET6,
				&((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr,
				buf, sizeof(buf)))
				continue;
		}
		if (add_iface_addr(ifc, cur->ifa_addr->sa_family, buf))
			goto fail;
	}
	freeifaddrs(ifa);
	return 0;
fail:
	freeifaddrs(ifa);
	return -1;
}

/*
 * read_first_line - read and trim the first line from @path.
 * @path: procfs/sysfs-style file path to read.
 *
 * Returns a caller-owned string, or NULL on open/read/allocation failure.
 */
static char *read_first_line(const char *path)
{
	int fd;
	char *buf;
	ssize_t len;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	buf = malloc(1024);
	if (!buf) {
		close(fd);
		return NULL;
	}
	len = read(fd, buf, 1023);
	close(fd);
	if (len <= 0) {
		free(buf);
		return NULL;
	}
	buf[len] = 0;
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = 0;
	return buf;
}

/*
 * extract_unit_from_cgroup - best-effort unit name lookup for @pid.
 * @pid: process ID whose /proc/<pid>/cgroup is inspected.
 *
 * Returns a caller-owned unit/scope name, or NULL if not found/readable.
 */
static char *extract_unit_from_cgroup(int pid)
{
	char path[64], line[512];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
	f = fopen(path, "rte");
	if (!f)
		return NULL;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		char *s;
		s = strstr(line, ".service");
		if (!s)
			s = strstr(line, ".scope");
		if (s) {
			while (s > line && *s != '/')
				s--;
			if (*s == '/')
				s++;
			char *e = s;
			while (*e && *e != '\n' && *e != '/')
				e++;
			*e = 0;
			fclose(f);
			return xstrdup(s);
		}
	}
	fclose(f);
	return NULL;
}

/*
 * caps_summary_for_pid - format capability summary for one process.
 * @pid: process ID inspected through libcap-ng APIs.
 * @privileged: out flag set when notable privileged effective caps exist.
 * @has_amb: out flag set when ambient capabilities are present.
 * @has_bnd: out flag set when bounding set entries are present.
 *
 * Returns caller-owned summary text; errors degrade to "(none)" style text.
 */
static char *caps_summary_for_pid(int pid, int *privileged, int *has_amb,
	int *has_bnd)
{
	char out[4096];
	int i, first = 1;
	capng_results_t c;

	*privileged = 0;
	*has_amb = 0;
	*has_bnd = 0;

	capng_clear(CAPNG_SELECT_ALL);
	capng_setpid(pid);
	if (capng_get_caps_process())
		return xstrdup("(none)");

	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_ADMIN) ||
	    capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_PTRACE) ||
	    capng_have_capability(CAPNG_EFFECTIVE, CAP_DAC_READ_SEARCH) ||
	    capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_ADMIN) ||
	    capng_have_capability(CAPNG_EFFECTIVE, CAP_NET_RAW))
		*privileged = 1;

	c = capng_have_capabilities(CAPNG_SELECT_CAPS);
	if (c == CAPNG_FULL)
		strcpy(out, "(full)");
	else if (c <= CAPNG_NONE)
		strcpy(out, "(none)");
	else {
		out[0] = 0;
		for (i = 0; i <= CAP_LAST_CAP; i++) {
			if (!capng_have_capability(CAPNG_PERMITTED, i))
				continue;
			const char *name = capng_capability_to_name(i);
			if (!name)
				continue;
			if (!first)
				strcat(out, ", ");
			if (strncmp(name, "cap_", 4) == 0)
				name += 4;
			strcat(out, name);
			first = 0;
		}
		if (out[0] == 0)
			strcpy(out, "(none)");
	}
	if (capng_have_capabilities(CAPNG_SELECT_AMBIENT) > CAPNG_NONE)
		*has_amb = 1;
	if (capng_have_capabilities(CAPNG_SELECT_BOUNDS) > CAPNG_NONE)
		*has_bnd = 1;
	if (*has_amb)
		strcat(out, " [ambient-present]");
	if (*has_bnd)
		strcat(out, " [open-ended-bounding]");
	return xstrdup(out);
}

/*
 * parse_status_defenses - read process hardening metadata into @d.
 * @pid: process ID whose procfs status/attr files are parsed.
 * @uid: process real UID, used for root/non-root interpretation.
 * @d: destination struct receiving caller-freed string fields.
 * @securebits_nondefault: out flag indicating meaningful securebits data.
 * @secbits_raw: out raw securebits value when present.
 *
 * Missing fields are tolerated; function leaves best-effort defaults.
 * Returns no value.
 */
static void parse_status_defenses(int pid, int uid, struct defense_info *d,
	int *securebits_nondefault, unsigned long *secbits_raw)
{
	char path[64], line[512];
	FILE *f;
	unsigned long secbits = 0;
	int seen_secbits = 0;

	d->runs_as_nonroot = xstrdup(uid != 0 ? "yes" : "no");
	d->no_new_privs = xstrdup("unknown");
	d->seccomp = xstrdup("disabled");
	d->lsm_label = NULL;
	d->securebits = NULL;
	d->securebits_locked = NULL;
	*securebits_nondefault = 0;
	*secbits_raw = 0;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "rte");
	if (!f)
		return;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		unsigned long val;
		if (sscanf(line, "NoNewPrivs:\t%lu", &val) == 1) {
			free(d->no_new_privs);
			d->no_new_privs = xstrdup(val ? "yes" : "no");
		} else if (sscanf(line, "Seccomp:\t%lu", &val) == 1) {
			free(d->seccomp);
			if (val == 0)
				d->seccomp = xstrdup("disabled");
			else if (val == 1)
				d->seccomp = xstrdup("strict");
			else
				d->seccomp = xstrdup("filter");
		} else if (sscanf(line, "Secbits:\t%lx", &secbits) == 1) {
			seen_secbits = 1;
		}
	}
	fclose(f);

	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	d->lsm_label = read_first_line(path);

	if (seen_secbits)
		*secbits_raw = secbits;
	if (uid == 0 || (seen_secbits && secbits != 0)) {
		char buf[256];
		/*
		 * Keep this decode local and explicit so reviewers can audit each
		 * bit's textual interpretation without cross-referencing helpers.
		 */
		int keep = !!(secbits & 0x10);
		int nofix = !!(secbits & 0x04);
		int noroot = !!(secbits & 0x01);
		int locked = !!(secbits & (0x20 | 0x08 | 0x02));
		snprintf(buf, sizeof(buf),
			"keep_caps=%s no_setuid_fixup=%s noroot=%s",
			keep ? "yes" : "no",
			nofix ? "yes" : "no",
			noroot ? "yes" : "no");
		d->securebits = xstrdup(buf);
		d->securebits_locked = xstrdup(locked ? "yes" : "no");
		*securebits_nondefault = 1;
	}
}

/*
 * add_process - collect process metadata and append it to @m.
 * @m: model taking ownership of the created process_info on success.
 * @pid: numeric process ID to read from /proc.
 *
 * Returns stored process pointer on success, or NULL on parse/allocation error.
 */
static struct process_info *add_process(struct model *m, int pid)
{
	char path[64], line[256], comm[64] = "";
	FILE *f;
	int uid = -1;
	int has_amb = 0, has_bnd = 0;
	int secure_nondefault = 0;
	unsigned long secbits_raw = 0;
	struct process_info *p;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "rte");
	if (!f)
		return NULL;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Name:\t%63s", comm) == 1)
			continue;
		if (sscanf(line, "Uid:\t%d", &uid) == 1)
			continue;
	}
	fclose(f);
	if (uid < 0)
		return NULL;

	p = calloc(1, sizeof(*p));
	if (!p) {
		fprintf(stderr, "Out of memory\n");
		return NULL;
	}
	p->pid = pid;
	p->uid = uid;
	p->comm = xstrdup(comm[0] ? comm : "?");
	p->unit = extract_unit_from_cgroup(pid);
	p->caps = caps_summary_for_pid(pid, &p->has_privileged_caps,
		&has_amb, &has_bnd);
	parse_status_defenses(pid, uid, &p->defenses, &secure_nondefault,
		&secbits_raw);
	p->securebits_locked = p->defenses.securebits_locked &&
		strcmp(p->defenses.securebits_locked, "yes") == 0;
	if (!p->comm || !p->caps || !p->defenses.runs_as_nonroot ||
	    !p->defenses.no_new_privs || !p->defenses.seccomp)
		goto fail;

	if (m->procs_n == m->procs_cap && vec_grow((void **)&m->procs,
	    &m->procs_cap, sizeof(struct process_info *)))
		goto fail;
	m->procs[m->procs_n++] = p;
	return p;

fail:
	free_process(p);
	return NULL;
}

/*
 * add_inode_proc - add inode->process ownership mapping into @m.
 * @m: model containing inode map storage.
 * @inode: socket inode key from procfs/netlink tables.
 * @p: process entry pointer that must remain valid for @m lifetime.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int add_inode_proc(struct model *m, unsigned long inode,
	struct process_info *p)
{
	size_t i, j;
	struct inode_proc *ip = NULL;

	for (i = 0; i < m->inode_n; i++) {
		if (m->inode_map[i].inode == inode) {
			ip = &m->inode_map[i];
			break;
		}
	}
	if (!ip) {
		if (m->inode_n == m->inode_cap && vec_grow((void **)&m->inode_map,
		    &m->inode_cap, sizeof(struct inode_proc)))
			return -1;
		ip = &m->inode_map[m->inode_n++];
		memset(ip, 0, sizeof(*ip));
		ip->inode = inode;
	}
	for (j = 0; j < ip->n; j++)
		if (ip->procs[j]->pid == p->pid)
			return 0;
	if (ip->n == ip->cap && vec_grow((void **)&ip->procs, &ip->cap,
	    sizeof(struct process_info *)))
		return -1;
	ip->procs[ip->n++] = p;
	return 0;
}

/*
 * collect_proc_inodes - build inode ownership map from /proc/<pid>/fd links.
 * @m: model receiving process entries and inode->process associations.
 *
 * This is best-effort and skips tasks/fds hidden by permissions or races.
 * Returns no value.
 */
static void collect_proc_inodes(struct model *m)
{
	DIR *d;
	struct dirent *ent;

	d = opendir("/proc");
	if (!d)
		return;
	while ((ent = readdir(d))) {
		int pid;
		DIR *fds;
		struct dirent *fdent;
		char fdpath[64];
		struct process_info *p;

		if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
			continue;
		pid = atoi(ent->d_name);
		if (pid <= 0)
			continue;
		p = add_process(m, pid);
		if (!p)
			continue;
		snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
		fds = opendir(fdpath);
		if (!fds)
			continue;
		while ((fdent = readdir(fds))) {
			char lpath[128], link[256], *s;
			ssize_t l;
			unsigned long inode;

			if (fdent->d_name[0] == '.')
				continue;
			snprintf(lpath, sizeof(lpath), "%s/%s", fdpath, fdent->d_name);
			l = readlink(lpath, link, sizeof(link) - 1);
			if (l < 0)
				continue;
			link[l] = 0;
			/*
			 * procfs may expose socket links in kernel-dependent formats.
			 * Handle both common "socket:[inode]" and "[0000]:inode" forms.
			 */
			if (strncmp(link, "socket:[", 8) == 0) {
				s = link + 8;
			} else if (strncmp(link, "[0000]:", 7) == 0) {
				s = link + 7;
			} else {
				continue;
			}
			inode = strtoul(s, NULL, 10);
			if (inode)
				add_inode_proc(m, inode, p);
		}
		closedir(fds);
	}
	closedir(d);
}

/*
 * lookup_inode - locate inode ownership entry in @m.
 *
 * Returns mutable map entry pointer, or NULL if inode is unknown.
 */
static struct inode_proc *lookup_inode(struct model *m, unsigned long inode)
{
	size_t i;

	for (i = 0; i < m->inode_n; i++)
		if (m->inode_map[i].inode == inode)
			return &m->inode_map[i];
	return NULL;
}

/*
 * add_endpoint - add/merge one inet or packet endpoint in @m.
 * @m: model receiving endpoint data.
 * @proto/@bind/@ifname/@ifaddr: copied strings for endpoint identity.
 * @port/@plane/@wildcard/@loopback: endpoint attributes for rendering/flags.
 * @ip: inode-owner mapping whose process pointers are attached to endpoint.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int add_endpoint(struct model *m, const char *proto, const char *bind,
	unsigned int port, enum plane_kind plane, const char *ifname,
	const char *ifaddr, int wildcard, int loopback, struct inode_proc *ip)
{
	size_t i, j;
	struct endpoint *e;
	char label[256];

	if (strchr(bind, ':'))
		snprintf(label, sizeof(label), "%s:[%s]:%u", proto, bind, port);
	else
		snprintf(label, sizeof(label), "%s:%s:%u", proto, bind, port);

	for (i = 0; i < m->eps_n; i++) {
		e = &m->eps[i];
		if (strcmp(e->label, label) == 0 && strcmp(e->ifname, ifname) == 0 &&
		    strcmp(e->ifaddr, ifaddr) == 0)
			goto add_procs;
	}
	if (m->eps_n == m->eps_cap && vec_grow((void **)&m->eps, &m->eps_cap,
	    sizeof(struct endpoint)))
		return -1;
	e = &m->eps[m->eps_n++];
	memset(e, 0, sizeof(*e));
	e->proto = xstrdup(proto);
	e->bind = xstrdup(bind);
	e->label = xstrdup(label);
	e->port = port;
	e->vsock_cid = 0;
	e->has_vsock = 0;
	e->plane = plane;
	e->ifname = xstrdup(ifname);
	e->ifaddr = xstrdup(ifaddr);
	e->wildcard_bind = wildcard;
	e->loopback_only = loopback;
	if (!e->proto || !e->bind || !e->label || !e->ifname || !e->ifaddr)
		return -1;
add_procs:
	for (j = 0; j < ip->n; j++) {
		size_t k;
		for (k = 0; k < e->procs_n; k++)
			if (e->procs[k]->pid == ip->procs[j]->pid)
				goto next;
		if (e->procs_n == e->procs_cap && vec_grow((void **)&e->procs,
		    &e->procs_cap, sizeof(struct process_info *)))
			return -1;
		e->procs[e->procs_n++] = ip->procs[j];
next:
		;
	}
	return 0;
}

/*
 * add_vsock_endpoint - add/merge one VSOCK endpoint in @m.
 * @m: model receiving endpoint data.
 * @type: socket type label (stream/dgram/seqpacket) copied into model.
 * @cid/@port: source CID/port; @cid may be VMADDR_CID_ANY.
 * @ip: inode-owner mapping whose process pointers are attached to endpoint.
 *
 * Returns 0 on success, -1 on allocation failure.
 */
static int add_vsock_endpoint(struct model *m, const char *type,
	unsigned int cid, unsigned int port, struct inode_proc *ip)
{
	size_t i, j;
	struct endpoint *e;
	char label[128];
	char cidbuf[32];

	if (cid == VMADDR_CID_ANY)
		strcpy(cidbuf, "ANY");
	else
		snprintf(cidbuf, sizeof(cidbuf), "%u", cid);
	snprintf(label, sizeof(label), "%s:cid=%s:%u", type, cidbuf, port);

	for (i = 0; i < m->eps_n; i++) {
		e = &m->eps[i];
		if (e->plane == PLANE_VSOCK && strcmp(e->label, label) == 0)
			goto add_procs;
	}
	if (m->eps_n == m->eps_cap && vec_grow((void **)&m->eps, &m->eps_cap,
	    sizeof(struct endpoint)))
		return -1;
	e = &m->eps[m->eps_n++];
	memset(e, 0, sizeof(*e));
	e->proto = xstrdup(type);
	e->bind = xstrdup(cidbuf);
	e->label = xstrdup(label);
	e->port = port;
	e->vsock_cid = cid;
	e->has_vsock = 1;
	e->plane = PLANE_VSOCK;
	e->ifname = xstrdup("");
	e->ifaddr = xstrdup("");
	if (!e->proto || !e->bind || !e->label || !e->ifname || !e->ifaddr)
		return -1;

add_procs:
	for (j = 0; j < ip->n; j++) {
		size_t k;

		for (k = 0; k < e->procs_n; k++)
			if (e->procs[k]->pid == ip->procs[j]->pid)
				goto next;
		if (e->procs_n == e->procs_cap && vec_grow((void **)&e->procs,
		    &e->procs_cap, sizeof(struct process_info *)))
			return -1;
		e->procs[e->procs_n++] = ip->procs[j];
next:
		;
	}
	return 0;
}

/*
 * endpoint_to_ifaces - project one inet bind onto iface/address groupings.
 * @m: model containing iface inventory and endpoint lists.
 * @proto/@af/@bind/@port: socket identity from procfs/sock_diag.
 * @ip: inode-owner mapping used to attach owning processes.
 *
 * Wildcard binds expand across non-loopback ifaces in current netns.
 * Returns no value.
 */
static void endpoint_to_ifaces(struct model *m, const char *proto, int af,
	const char *bind, unsigned int port, struct inode_proc *ip)
{
	size_t i, j;
	int wildcard = str_is_wildcard(af, bind);
	int loopback = str_is_loopback(af, bind);
	int matched = 0;

	for (i = 0; i < m->ifaces_n; i++) {
		struct iface_info *ifc = &m->ifaces[i];
		for (j = 0; j < ifc->addrs_n; j++) {
			if (ifc->addrs[j].af != af)
				continue;
			if (wildcard) {
				/*
				 * 0.0.0.0/:: listeners are treated as externally reachable; keep
				 * loopback out of this expansion to avoid duplicate exposure rows.
				 */
				if (strcmp(ifc->name, "lo") == 0)
					continue;
				add_endpoint(m, proto, bind, port, PLANE_INET_EXTERNAL,
					ifc->name, ifc->addrs[j].addr, 1, 0, ip);
				matched = 1;
			} else if (strcmp(ifc->addrs[j].addr, bind) == 0) {
				enum plane_kind plane = loopback ?
					PLANE_INET_LOOPBACK : PLANE_INET_EXTERNAL;
				add_endpoint(m, proto, bind, port, plane, ifc->name,
					ifc->addrs[j].addr, 0, loopback, ip);
				matched = 1;
			}
		}
	}
	if (!matched)
		add_endpoint(m, proto, bind, port,
			loopback ? PLANE_INET_LOOPBACK : PLANE_INET_EXTERNAL,
			loopback ? "lo" : "unknown", bind, wildcard, loopback, ip);
}

/*
 * parse_inet_file - parse one procfs inet socket table into endpoints.
 * @m: model receiving endpoint mappings.
 * @path: procfs table path (tcp/udp/raw variants).
 * @proto: protocol label used in rendered endpoint names.
 * @af: address family used to decode local bind addresses.
 *
 * Non-listeners/unowned sockets are skipped; output is best-effort.
 * Returns no value.
 */
static void parse_inet_file(struct model *m, const char *path,
	const char *proto, int af)
{
	FILE *f;
	char line[512];
	int row = 0;

	f = fopen(path, "rte");
	if (!f)
		return;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		unsigned int lport, rport, state;
		unsigned long txq, rxq, tmr, when, retr, inode;
		int d, uid, timeout;
		char laddrh[96], raddrh[96], more[128];
		char addr[INET6_ADDRSTRLEN];
		struct inode_proc *ip;
		more[0] = 0;
		if (!row++)
			continue;
		if (sscanf(line, "%d: %95[0-9A-Fa-f]:%X %95[0-9A-Fa-f]:%X %X "
			"%lX:%lX %lX:%lX %lX %d %d %lu %127s",
			&d, laddrh, &lport, raddrh, &rport, &state, &txq, &rxq,
			&tmr, &when, &retr, &uid, &timeout, &inode, more) < 14)
			continue;
		if ((strcmp(proto, "tcp") == 0 ||
		     strcmp(proto, "tcp6") == 0) && state != 0x0A)
			continue;
		if ((strcmp(proto, "udp") == 0 ||
		     strcmp(proto, "udp6") == 0 ||
		     strcmp(proto, "udplite") == 0 ||
		     strcmp(proto, "udplite6") == 0) && lport == 0)
			continue;
		ip = lookup_inode(m, inode);
		if (!ip)
			continue;
		if (af == AF_INET) {
			unsigned int b0, b1, b2, b3;
			if (sscanf(laddrh, "%2x%2x%2x%2x", &b3, &b2, &b1, &b0) != 4)
				continue;
			snprintf(addr, sizeof(addr), "%u.%u.%u.%u", b0, b1, b2, b3);
		} else {
			unsigned char bytes[16] = { 0 };
			int i;
			if (strlen(laddrh) != 32)
				continue;
			for (i = 0; i < 4; i++) {
				unsigned int w;
				unsigned int be;

				/* procfs stores each 32-bit word in little-endian hex. */
				if (sscanf(laddrh + (i * 8), "%8x", &w) != 1)
					continue;
				be = htonl(w);
				memcpy(bytes + (i * 4), &be, sizeof(be));
			}
			if (!inet_ntop(AF_INET6, bytes, addr, sizeof(addr)))
				continue;
		}
		endpoint_to_ifaces(m, proto, af, addr, lport, ip);
	}
	fclose(f);
}

/*
 * parse_packet_file - parse /proc/net/packet and add packet endpoints.
 * @m: model receiving packet-plane endpoint/process mappings.
 *
 * Visibility depends on current netns and procfs access permissions.
 * Returns no value.
 */
static void parse_packet_file(struct model *m)
{
	FILE *f;
	char line[512], ifn[IF_NAMESIZE];
	int row = 0;

	f = fopen("/proc/net/packet", "rte");
	if (!f)
		return;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		unsigned long sk, inode;
		unsigned int ref, type, proto, iface, r, rmem, uid;
		struct inode_proc *ip;
		char bind[64], addr[64], name[64];

		if (!row++)
			continue;
		if (sscanf(line, "%lX %u %u %X %u %u %u %u %lu",
			&sk, &ref, &type, &proto, &iface, &r, &rmem, &uid,
			&inode) < 9)
			continue;
		ip = lookup_inode(m, inode);
		if (!ip)
			continue;
		if (!if_indextoname(iface, ifn))
			strcpy(ifn, "unknown");
		snprintf(bind, sizeof(bind), "%s", ifn);
		snprintf(addr, sizeof(addr), "ifindex:%u", iface);
		snprintf(name, sizeof(name), "packet");
		add_endpoint(m, name, bind, proto, PLANE_PACKET, ifn, addr,
			0, 0, ip);
	}
	fclose(f);
}

/*
 * parse_u32_hex_or_dec - parse @s as decimal or hexadecimal u32.
 * @s: numeric token from procfs/netlink text fields.
 * @out: destination value on successful parse.
 *
 * Returns 0 on success, -1 if @s is not a valid integer token.
 */
static int parse_u32_hex_or_dec(const char *s, unsigned int *out)
{
	char *end;
	unsigned long v;
	int base = 10;
	const char *p;

	for (p = s; *p; p++) {
		if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
			base = 16;
			break;
		}
	}
	if (strncmp(s, "0x", 2) == 0 || strncmp(s, "0X", 2) == 0)
		base = 16;
	if (base == 10 && strlen(s) > 3 && s[0] == '0')
		base = 16;
	v = strtoul(s, &end, base);
	if (end == s || *end)
		return -1;
	*out = (unsigned int)v;
	return 0;
}

/*
 * parse_vsock_file - fallback VSOCK parser using /proc/net/vsock.
 * @m: model receiving parsed VSOCK endpoint/process mappings.
 *
 * Used when sock_diag support is unavailable or denied.
 * Returns no value.
 */
static void parse_vsock_file(struct model *m)
{
	FILE *f;
	char line[512];

	f = fopen("/proc/net/vsock", "rte");
	if (!f)
		return;
	__fsetlocking(f, FSETLOCKING_BYCALLER);
	while (fgets(line, sizeof(line), f)) {
		char work[512];
		char *tok[24];
		char *save = NULL;
		char *local, *s, *sep;
		int tcnt = 0;
		unsigned long inode;
		unsigned int st, type, cid, port;
		struct inode_proc *ip;
		const char *kind;

		if (strstr(line, "Local") || strstr(line, "local") ||
		    strstr(line, "Num"))
			continue;
		snprintf(work, sizeof(work), "%s", line);
		s = strtok_r(work, " \t\n", &save);
		while (s && tcnt < (int)(sizeof(tok) / sizeof(tok[0]))) {
			tok[tcnt++] = s;
			s = strtok_r(NULL, " \t\n", &save);
		}
		if (tcnt < 5)
			continue;
		local = NULL;
		for (int i = 0; i < tcnt; i++) {
			if (strchr(tok[i], ':')) {
				local = tok[i];
				break;
			}
		}
		if (!local)
			continue;
		sep = strchr(local, ':');
		if (!sep)
			continue;
		*sep = '\0';
		if (parse_u32_hex_or_dec(local, &cid) ||
		    parse_u32_hex_or_dec(sep + 1, &port))
			continue;

		if (parse_u32_hex_or_dec(tok[tcnt - 2], &st))
			continue;
		if (parse_u32_hex_or_dec(tok[tcnt - 3], &type))
			continue;
		inode = strtoul(tok[tcnt - 1], NULL, 10);
		if (!inode)
			continue;

		if (type == SOCK_STREAM) {
			if (st != 0x0A)
				continue;
			kind = "stream";
		} else if (type == SOCK_DGRAM) {
			if (port == 0)
				continue;
			kind = "dgram";
		} else {
			continue;
		}

		ip = lookup_inode(m, inode);
		if (!ip)
			continue;
		add_vsock_endpoint(m, kind, cid, port, ip);
	}
	fclose(f);
}

/*
 * vsock_type_to_name - map VSOCK socket type to display label.
 *
 * Returns static string label, or NULL for unknown/unsupported type.
 */
static const char *vsock_type_to_name(unsigned int type)
{
	if (type == SOCK_STREAM)
		return "stream";
	if (type == SOCK_DGRAM)
		return "dgram";
	if (type == SOCK_SEQPACKET)
		return "seqpacket";
	return NULL;
}

#ifdef HAVE_LINUX_VM_SOCKETS_DIAG_H
/*
 * parse_vsock_diag_messages - consume VSOCK sock_diag dump replies.
 * @m: model receiving VSOCK endpoint/process mappings.
 * @fd: open NETLINK_SOCK_DIAG socket with pending VSOCK responses.
 *
 * Returns 0 on NLMSG_DONE, or -1 on malformed/error netlink messages.
 */
static int parse_vsock_diag_messages(struct model *m, int fd)
{
	char buf[8192];
	ssize_t len;

	while (1) {
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (len == 0)
			return -1;

		struct nlmsghdr *nlh;
		ssize_t rem = len;

		for (nlh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nlh, rem);
		     nlh = NLMSG_NEXT(nlh, rem)) {
			struct vsock_diag_msg *r;
			struct inode_proc *ip;
			const char *kind;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e;

				if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*e)))
					return -1;
				e = NLMSG_DATA(nlh);
				if (e->error == 0)
					continue;
				errno = -e->error;
				return -1;
			}
			if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*r)))
				continue;

			r = NLMSG_DATA(nlh);
			if (r->vdiag_family != AF_VSOCK)
				continue;
			kind = vsock_type_to_name(r->vdiag_type);
			if (!kind)
				continue;

			if (r->vdiag_type == SOCK_STREAM &&
			    r->vdiag_state != TCP_LISTEN)
				continue;
			if ((r->vdiag_type == SOCK_DGRAM ||
			     r->vdiag_type == SOCK_SEQPACKET) &&
			    r->vdiag_src_port == 0)
				continue;

			ip = lookup_inode(m, r->vdiag_ino);
			if (!ip)
				continue;

			diag_dbg("vsock type=%u state=%u src=%u:%u dst=%u:%u ino=%u",
				r->vdiag_type, r->vdiag_state, r->vdiag_src_cid,
				r->vdiag_src_port, r->vdiag_dst_cid, r->vdiag_dst_port,
				r->vdiag_ino);
			add_vsock_endpoint(m, kind, r->vdiag_src_cid,
				r->vdiag_src_port, ip);
		}
	}
}

/*
 * parse_vsock_diag - request VSOCK listener dump via sock_diag netlink.
 * @m: model receiving parsed VSOCK endpoint/process mappings.
 *
 * Returns 0 on success, -1 with errno on permission/support/socket errors.
 */
static int parse_vsock_diag(struct model *m)
{
	struct {
		struct nlmsghdr nlh;
		struct vsock_diag_req req;
	} req;
	struct sockaddr_nl sa;
	int fd;
	int rc = -1;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (fd < 0)
		return -1;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.req));
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.req.sdiag_family = AF_VSOCK;
	req.req.sdiag_protocol = 0;
	req.req.vdiag_states = ~0U;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0;

	if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto out;
	rc = parse_vsock_diag_messages(m, fd);
out:
	close(fd);
	return rc;
}
#else
/*
 * parse_vsock_diag - unsupported-build stub for VSOCK sock_diag path.
 * @m: unused model pointer.
 *
 * Returns -1 and sets errno=EOPNOTSUPP.
 */
static int parse_vsock_diag(struct model *m)
{
	(void)m;
	errno = EOPNOTSUPP;
	return -1;
}
#endif

/*
 * parse_diag_messages - consume inet sock_diag replies for @proto/@af.
 * @m: model receiving parsed endpoint mappings.
 * @fd: open NETLINK_SOCK_DIAG socket with pending responses.
 * @proto: requested protocol (SCTP/DCCP).
 * @af: requested address family (AF_INET/AF_INET6).
 *
 * Returns 0 on NLMSG_DONE, or -1 on malformed/error netlink messages.
 */
static int parse_diag_messages(struct model *m, int fd, int proto, int af)
{
	char buf[8192];
	ssize_t len;

	while (1) {
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (len == 0)
			return -1;

		diag_dbg("recv proto=%d af=%d len=%zd", proto, af, len);

		struct nlmsghdr *nlh;
		ssize_t rem = len;

		for (nlh = (struct nlmsghdr *)buf;
		     NLMSG_OK(nlh, rem);
		     nlh = NLMSG_NEXT(nlh, rem)) {
			struct inet_diag_msg *r;
			char addr[INET6_ADDRSTRLEN];
			unsigned int port;
			struct inode_proc *ip;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e;

				if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*e)))
					return -1;
				e = NLMSG_DATA(nlh);
				if (e->error == 0)
					continue;
				errno = -e->error;
				diag_dbg("error proto=%d af=%d err=%d", proto, af,
					-e->error);
				return -1;
			}
			if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*r)))
				continue;

			r = NLMSG_DATA(nlh);
			ip = lookup_inode(m, r->idiag_inode);
			if (!ip)
				continue;
			port = ntohs(r->id.idiag_sport);
			if (!port)
				continue;

			if (af == AF_INET) {
				if (!inet_ntop(AF_INET, r->id.idiag_src, addr,
				    sizeof(addr)))
					continue;
			} else {
				if (!inet_ntop(AF_INET6, r->id.idiag_src, addr,
				    sizeof(addr)))
					continue;
			}
			endpoint_to_ifaces(m,
				proto == IPPROTO_SCTP ? "sctp" : "dccp",
				af, addr, port, ip);
		}
	}
}

/*
 * parse_diag_for_proto_af - issue one inet sock_diag listener dump request.
 * @m: model receiving parsed endpoint mappings.
 * @proto: protocol selector for the request.
 * @af: address family selector for the request.
 *
 * Best-effort helper; failures are tolerated by callers.
 * Returns no value.
 */
static void parse_diag_for_proto_af(struct model *m, int proto, int af)
{
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 req;
	} req;
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (fd < 0)
		return;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.req));
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.req.sdiag_family = af;
	req.req.sdiag_protocol = proto;
	req.req.idiag_states = 1U << TCP_LISTEN;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = 0;

	diag_dbg("send proto=%d af=%d len=%u", proto, af,
		req.nlh.nlmsg_len);
	if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto out;
	parse_diag_messages(m, fd, proto, af);
out:
	close(fd);
}

/*
 * parse_diag_listeners - collect SCTP/DCCP listeners via sock_diag.
 * @m: model receiving discovered listener endpoints.
 *
 * Returns no value.
 */
static void parse_diag_listeners(struct model *m)
{
	parse_diag_for_proto_af(m, IPPROTO_SCTP, AF_INET);
	parse_diag_for_proto_af(m, IPPROTO_SCTP, AF_INET6);
	parse_diag_for_proto_af(m, IPPROTO_DCCP, AF_INET);
	parse_diag_for_proto_af(m, IPPROTO_DCCP, AF_INET6);
}

/*
 * collect_endpoints - gather all endpoint classes into @m.
 * @m: model receiving inet, diag, packet, and vsock endpoint mappings.
 *
 * Data source is current netns procfs/netlink visibility.
 * Returns no value.
 */
static void collect_endpoints(struct model *m)
{
	parse_inet_file(m, "/proc/net/tcp", "tcp", AF_INET);
	parse_inet_file(m, "/proc/net/tcp6", "tcp6", AF_INET6);
	parse_inet_file(m, "/proc/net/udp", "udp", AF_INET);
	parse_inet_file(m, "/proc/net/udp6", "udp6", AF_INET6);
	parse_inet_file(m, "/proc/net/udplite", "udplite", AF_INET);
	parse_inet_file(m, "/proc/net/udplite6", "udplite6", AF_INET6);
	parse_inet_file(m, "/proc/net/raw", "raw", AF_INET);
	parse_inet_file(m, "/proc/net/raw6", "raw6", AF_INET6);
	parse_diag_listeners(m);
	parse_packet_file(m);
	if (parse_vsock_diag(m) < 0) {
		diag_dbg("vsock diag unavailable (%s), falling back to /proc",
			strerror(errno));
		parse_vsock_file(m);
	}
}

/*
 * wrap_to - choose a safe wrap index for one output line.
 * @text: source string being wrapped.
 * @from: starting offset in @text.
 * @limit: maximum columns to consume from @from.
 *
 * Returns next index to continue rendering from.
 */
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

/*
 * print_tree_node - render one tree node line (with wrapping) to stdout.
 * @prefix: precomputed branch prefix glyphs.
 * @is_last: non-zero when this node is the last child.
 * @txt: node text to render.
 * @width: target display width used for wrapping.
 *
 * Returns no value.
 */
static void print_tree_node(const char *prefix, int is_last, const char *txt,
	int width)
{
	char head[512];
	char cont[512];
	int pos = 0;
	int first = 1;

	snprintf(head, sizeof(head), "%s%s", prefix,
		is_last ? "└─ " : "├─ ");
	snprintf(cont, sizeof(cont), "%s%s", prefix,
		is_last ? "   " : "│  ");
	while (1) {
		const char *lead = first ? head : cont;
		int lead_len = strlen(lead);
		int avail = width - lead_len;
		int to;

		if (avail < 10)
			avail = 10;
		if (!txt[pos]) {
			printf("%s\n", lead);
			return;
		}
		to = wrap_to(txt, pos, avail);
		printf("%s%.*s\n", lead, to - pos, txt + pos);
		while (txt[to] == ' ')
			to++;
		pos = to;
		first = 0;
		if (!txt[pos])
			return;
	}
}

/*
 * build_child_prefix - extend tree prefix glyphs for child nodes.
 * @dst: output buffer receiving generated prefix text.
 * @dst_sz: size of @dst in bytes.
 * @prefix: parent prefix string.
 * @parent_is_last: non-zero when parent is the last sibling.
 *
 * Returns no value.
 */
static void build_child_prefix(char *dst, size_t dst_sz, const char *prefix,
	int parent_is_last)
{
	snprintf(dst, dst_sz, "%s%s", prefix,
		parent_is_last ? "   " : "│  ");
}

/*
 * endpoint_cmp - qsort comparator for stable endpoint grouping.
 *
 * Sort order is plane, interface name, interface address, then label.
 */
static int endpoint_cmp(const void *a, const void *b)
{
	const struct endpoint *ea = a, *eb = b;
	if (ea->plane != eb->plane)
		return ea->plane - eb->plane;
	if (strcmp(ea->ifname, eb->ifname) != 0)
		return strcmp(ea->ifname, eb->ifname);
	if (strcmp(ea->ifaddr, eb->ifaddr) != 0)
		return strcmp(ea->ifaddr, eb->ifaddr);
	return strcmp(ea->label, eb->label);
}

/*
 * render_tree - print human-readable advanced report as a tree.
 * @m: model to render; endpoint array is sorted in place before printing.
 *
 * Returns no value.
 */
static void render_tree(struct model *m)
{
	size_t i;
	int planes[4];
	size_t plane_n = 0;
	int width = get_width();

	qsort(m->eps, m->eps_n, sizeof(struct endpoint), endpoint_cmp);
	puts("netcap --advanced");

	for (i = 0; i < 4; i++) {
		size_t j;
		for (j = 0; j < m->eps_n; j++) {
			if (m->eps[j].plane == (enum plane_kind)i) {
				planes[plane_n++] = i;
				break;
			}
		}
	}

	for (i = 0; i < plane_n; i++) {
		int plane = planes[i];
		int plane_last = (i + 1 == plane_n);
		char pfx_plane[256] = "";
		char pfx_iface[256];
		const char *plane_name = plane == PLANE_INET_EXTERNAL ?
			"INET (external)" :
			plane == PLANE_INET_LOOPBACK ? "INET (loopback)" :
			plane == PLANE_PACKET ? PLANE_PACKET_NAME : "VSOCK";
		size_t j = 0;

		print_tree_node(pfx_plane, plane_last, plane_name, width);
		build_child_prefix(pfx_iface, sizeof(pfx_iface), pfx_plane,
			plane_last);
		if (plane == PLANE_VSOCK) {
			/* VSOCK has no iface/address hierarchy, so print endpoint-first. */
			for (j = 0; j < m->eps_n; j++) {
				struct endpoint *e = &m->eps[j];
				char pfx_proc[256];
				int ep_last;
				size_t k;

				if (e->plane != PLANE_VSOCK)
					continue;
				ep_last = 1;
				for (size_t n = j + 1; n < m->eps_n; n++) {
					if (m->eps[n].plane == PLANE_VSOCK) {
						ep_last = 0;
						break;
					}
				}
				print_tree_node(pfx_iface, ep_last, e->label, width);
				build_child_prefix(pfx_proc, sizeof(pfx_proc), pfx_iface,
					ep_last);
				for (k = 0; k < e->procs_n; k++) {
					struct process_info *p = e->procs[k];
					char pfx_child[256], pfx_def[256], pfx_flags[256];
					char line[512];
					struct strvec flags = { 0 };
					const char *def_nodes[8];
					char def_buf[8][512];
					size_t def_n = 0;
					size_t ai;
					int proc_last = (k + 1 == e->procs_n);

					snprintf(line, sizeof(line),
						"%s (pid=%d uid=%d%s%s)",
						p->comm, p->pid, p->uid,
						p->unit ? " unit=" : "",
						p->unit ? p->unit : "");
					print_tree_node(pfx_proc, proc_last, line, width);
					build_child_prefix(pfx_child, sizeof(pfx_child), pfx_proc,
						proc_last);

					snprintf(line, sizeof(line), "caps: %s", p->caps);
					print_tree_node(pfx_child, 0, line, width);

					snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
						"runs_as_nonroot: %s",
						p->defenses.runs_as_nonroot);
					def_nodes[def_n] = def_buf[def_n];
					def_n++;
					snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
						"no_new_privs: %s",
						p->defenses.no_new_privs);
					def_nodes[def_n] = def_buf[def_n];
					def_n++;
					snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
						"seccomp: %s", p->defenses.seccomp);
					def_nodes[def_n] = def_buf[def_n];
					def_n++;
					if (p->defenses.lsm_label) {
						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"lsm: %s",
							p->defenses.lsm_label);
						def_nodes[def_n] = def_buf[def_n];
					def_n++;
					}
					if (p->defenses.securebits) {
						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"securebits: %s",
							p->defenses.securebits);
						def_nodes[def_n] = def_buf[def_n];
					def_n++;
						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"securebits_locked: %s",
							p->defenses.securebits_locked);
						def_nodes[def_n] = def_buf[def_n];
					def_n++;
					}

					print_tree_node(pfx_child, 0, "defenses", width);
					build_child_prefix(pfx_def, sizeof(pfx_def), pfx_child, 0);
					for (ai = 0; ai < def_n; ai++)
						print_tree_node(pfx_def, ai + 1 == def_n,
							def_nodes[ai], width);

					push_str_unique(&flags, "hypervisor-plane");
					if (e->port == 22)
						push_str_unique(&flags,
							"ssh-on-vsock-port-22");
					if (p->has_privileged_caps)
						push_str_unique(&flags,
							"privileged-caps");
					if (p->securebits_locked)
						push_str_unique(&flags,
							"securebits-locked");

					print_tree_node(pfx_child, 1, "flags", width);
					build_child_prefix(pfx_flags, sizeof(pfx_flags),
						pfx_child, 1);
					if (flags.n == 0)
						print_tree_node(pfx_flags, 1, "(none)", width);
					else {
						for (ai = 0; ai < flags.n; ai++)
							print_tree_node(pfx_flags,
								ai + 1 == flags.n,
								flags.v[ai], width);
					}
					for (ai = 0; ai < flags.n; ai++)
						free(flags.v[ai]);
					free(flags.v);
				}
			}
			continue;
		}

		while (j < m->eps_n) {
			size_t iface_start, iface_end;
			char pfx_addr[256];
			char iface_line[160];
			int iface_last;

			if (m->eps[j].plane != (enum plane_kind)plane) {
				j++;
				continue;
			}
			iface_start = j;
			iface_end = j + 1;
			while (iface_end < m->eps_n &&
			       m->eps[iface_end].plane == (enum plane_kind)plane &&
			       strcmp(m->eps[iface_end].ifname,
				m->eps[iface_start].ifname) == 0)
				iface_end++;
			iface_last = 1;
			if (iface_end < m->eps_n &&
			    m->eps[iface_end].plane == (enum plane_kind)plane)
				iface_last = 0;

			snprintf(iface_line, sizeof(iface_line), "%s",
				m->eps[iface_start].ifname);
			print_tree_node(pfx_iface, iface_last, iface_line, width);
			build_child_prefix(pfx_addr, sizeof(pfx_addr), pfx_iface,
				iface_last);

			for (j = iface_start; j < iface_end; ) {
				size_t addr_start = j, addr_end;
				char pfx_ep[256];
				char addr_line[192];
				int addr_last;

				addr_end = j + 1;
				while (addr_end < iface_end &&
				       strcmp(m->eps[addr_end].ifaddr,
					m->eps[addr_start].ifaddr) == 0)
					addr_end++;
				addr_last = (addr_end == iface_end);

				snprintf(addr_line, sizeof(addr_line), "addr: %s",
					m->eps[addr_start].ifaddr);
				print_tree_node(pfx_addr, addr_last, addr_line, width);
				build_child_prefix(pfx_ep, sizeof(pfx_ep), pfx_addr,
					addr_last);

				for (j = addr_start; j < addr_end; j++) {
					struct endpoint *e = &m->eps[j];
					char pfx_proc[256];
					int ep_last = (j + 1 == addr_end);
					size_t k;

					print_tree_node(pfx_ep, ep_last, e->label, width);
					build_child_prefix(pfx_proc, sizeof(pfx_proc), pfx_ep,
						ep_last);

					for (k = 0; k < e->procs_n; k++) {
						struct process_info *p = e->procs[k];
						char pfx_child[256], pfx_def[256], pfx_flags[256];
						char line[512];
						struct strvec flags = { 0 };
						const char *def_nodes[8];
						char def_buf[8][512];
						size_t def_n = 0;
						size_t ai;
						int proc_last = (k + 1 == e->procs_n);

						snprintf(line, sizeof(line),
							"%s (pid=%d uid=%d%s%s)",
							p->comm, p->pid, p->uid,
							p->unit ? " unit=" : "",
							p->unit ? p->unit : "");
						print_tree_node(pfx_proc, proc_last, line, width);
						build_child_prefix(pfx_child, sizeof(pfx_child), pfx_proc,
							proc_last);

						snprintf(line, sizeof(line), "caps: %s", p->caps);
						print_tree_node(pfx_child, 0, line, width);

						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"runs_as_nonroot: %s", p->defenses.runs_as_nonroot);
						def_nodes[def_n] = def_buf[def_n];
						def_n++;
						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"no_new_privs: %s", p->defenses.no_new_privs);
						def_nodes[def_n] = def_buf[def_n];
						def_n++;
						snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
							"seccomp: %s", p->defenses.seccomp);
						def_nodes[def_n] = def_buf[def_n];
						def_n++;
						if (p->defenses.lsm_label) {
							snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
								"lsm: %s", p->defenses.lsm_label);
							def_nodes[def_n] = def_buf[def_n];
						def_n++;
						}
						if (p->defenses.securebits) {
							snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
								"securebits: %s", p->defenses.securebits);
							def_nodes[def_n] = def_buf[def_n];
						def_n++;
							snprintf(def_buf[def_n], sizeof(def_buf[def_n]),
								"securebits_locked: %s",
								p->defenses.securebits_locked);
							def_nodes[def_n] = def_buf[def_n];
						def_n++;
						}

						print_tree_node(pfx_child, 0, "defenses", width);
						build_child_prefix(pfx_def, sizeof(pfx_def), pfx_child, 0);
						for (ai = 0; ai < def_n; ai++)
							print_tree_node(pfx_def, ai + 1 == def_n,
								def_nodes[ai], width);

						if (e->wildcard_bind)
							push_str_unique(&flags, "wildcard-bind");
						if (e->loopback_only)
							push_str_unique(&flags, "loopback-only");
						if (p->has_privileged_caps)
							push_str_unique(&flags, "privileged-caps");
						if (p->securebits_locked)
							push_str_unique(&flags, "securebits-locked");

						print_tree_node(pfx_child, 1, "flags", width);
						build_child_prefix(pfx_flags, sizeof(pfx_flags),
							pfx_child, 1);
						if (flags.n == 0)
							print_tree_node(pfx_flags, 1, "(none)", width);
						else {
							for (ai = 0; ai < flags.n; ai++)
								print_tree_node(pfx_flags,
									ai + 1 == flags.n,
									flags.v[ai], width);
						}
						for (ai = 0; ai < flags.n; ai++)
							free(flags.v[ai]);
						free(flags.v);
					}
				}
			}
			j = iface_end;
		}
	}
}

/*
 * json_escape - write @s as a quoted JSON string to stdout.
 *
 * Control characters and quotes are escaped; caller handles separators.
 * Returns no value.
 */
static void json_escape(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	putchar('"');
	for (; *p; p++) {
		if (*p == '"')
			fputs("\\\"", stdout);
		else if (*p == '\\')
			fputs("\\\\", stdout);
		else if (*p < 0x20)
			printf("\\u%04x", *p);
		else
			putchar(*p);
	}
	putchar('"');
}

/*
 * render_json - print machine-readable advanced report JSON to stdout.
 * @m: model to render; endpoint array is sorted in place before printing.
 *
 * Returns no value.
 */
static void render_json(struct model *m)
{
	size_t i, j, k, l;

	qsort(m->eps, m->eps_n, sizeof(struct endpoint), endpoint_cmp);
	puts("{");
	puts("  \"schema_version\": 1,");
	puts("  \"planes\": [");
	for (i = 0; i < 4; i++) {
		const char *pname = i == PLANE_INET_EXTERNAL ? "INET" :
			i == PLANE_INET_LOOPBACK ? "INET" :
			i == PLANE_PACKET ? PLANE_PACKET_NAME : "VSOCK";
		const char *scope = i == PLANE_INET_EXTERNAL ? "external" :
			i == PLANE_INET_LOOPBACK ? "loopback" : NULL;
		int first_vsock = 1;
		int first_if = 1;

		printf("    {\"name\": ");
		json_escape(pname);
		if (scope) {
			printf(", \"scope\": ");
			json_escape(scope);
		}
		if (i == PLANE_VSOCK)
			puts(", \"endpoints\": [");
		else
			puts(", \"ifaces\": [");

		if (i == PLANE_VSOCK) {
			for (j = 0; j < m->eps_n; j++) {
				struct endpoint *ep = &m->eps[j];

				if (ep->plane != PLANE_VSOCK)
					continue;
				if (!first_vsock)
					puts(",");
				first_vsock = 0;
				printf("      {\"label\": ");
				json_escape(ep->label);
				printf(", \"vsock_type\": ");
				json_escape(ep->proto);
				printf(", \"cid\": ");
				if (ep->vsock_cid == VMADDR_CID_ANY)
					json_escape("ANY");
				else
					printf("%u", ep->vsock_cid);
				printf(", \"port\": %u", ep->port);
				puts(", \"processes\": [");
				for (size_t pi = 0; pi < ep->procs_n; pi++) {
					struct process_info *p = ep->procs[pi];
					printf("        {\"comm\": ");
					json_escape(p->comm);
					printf(", \"pid\": %d, \"uid\": %d", p->pid,
						p->uid);
					if (p->unit) {
						printf(", \"unit\": ");
						json_escape(p->unit);
					}
					printf(", \"caps\": ");
					json_escape(p->caps);
					printf(", \"defenses\": {\"runs_as_nonroot\": ");
					json_escape(p->defenses.runs_as_nonroot);
					printf(", \"no_new_privs\": ");
					json_escape(p->defenses.no_new_privs);
					printf(", \"seccomp\": ");
					json_escape(p->defenses.seccomp);
					if (p->defenses.lsm_label) {
						printf(", \"lsm\": ");
						json_escape(p->defenses.lsm_label);
					}
					if (p->defenses.securebits) {
						printf(", \"securebits\": ");
						json_escape(p->defenses.securebits);
						printf(", \"securebits_locked\": ");
						json_escape(p->defenses.securebits_locked);
					}
					printf("}, \"flags\": [");
					json_escape("hypervisor-plane");
					if (ep->port == 22) {
						printf(", ");
						json_escape("ssh-on-vsock-port-22");
					}
					if (p->has_privileged_caps) {
						printf(", ");
						json_escape("privileged-caps");
					}
					if (p->securebits_locked) {
						printf(", ");
						json_escape("securebits-locked");
					}
					printf("]}");
					if (pi + 1 != ep->procs_n)
						puts(",");
					else
						putchar('\n');
				}
				puts("      ]}");
			}
			puts("    ]}");
			if (i != 3)
				puts(",");
			continue;
		}

		for (j = 0; j < m->eps_n; j++) {
			const char *ifn = m->eps[j].ifname;
			int first_addr = 1;

			if (m->eps[j].plane != (enum plane_kind)i)
				continue;
			for (l = 0; l < j; l++) {
				if (m->eps[l].plane == (enum plane_kind)i &&
				    strcmp(m->eps[l].ifname, ifn) == 0)
					break;
			}
			if (l != j)
				continue;
			if (!first_if)
				puts(",");
			first_if = 0;
			printf("      {\"name\": ");
			json_escape(ifn);
			puts(", \"addrs\": [");

			for (k = 0; k < m->eps_n; k++) {
				const char *ifa = m->eps[k].ifaddr;
				int first_ep = 1;
				if (m->eps[k].plane != (enum plane_kind)i ||
				    strcmp(m->eps[k].ifname, ifn) != 0)
					continue;
				for (l = 0; l < k; l++) {
					if (m->eps[l].plane == (enum plane_kind)i &&
					    strcmp(m->eps[l].ifname, ifn) == 0 &&
					    strcmp(m->eps[l].ifaddr, ifa) == 0)
						break;
				}
				if (l != k)
					continue;
				if (!first_addr)
					puts(",");
				first_addr = 0;
				printf("        {\"addr\": ");
				json_escape(ifa);
				puts(", \"endpoints\": [");
				for (l = 0; l < m->eps_n; l++) {
					struct endpoint *ep = &m->eps[l];
					if (ep->plane != (enum plane_kind)i ||
					    strcmp(ep->ifname, ifn) != 0 ||
					    strcmp(ep->ifaddr, ifa) != 0)
						continue;
					if (!first_ep)
						puts(",");
					first_ep = 0;
					printf("          {\"label\": ");
					json_escape(ep->label);
					printf(", \"proto\": ");
					json_escape(ep->proto);
					printf(", \"bind\": ");
					json_escape(ep->bind);
					printf(", \"port\": %u", ep->port);
					puts(", \"processes\": [");
					for (size_t pi = 0; pi < ep->procs_n; pi++) {
						struct process_info *p = ep->procs[pi];
						printf("            {\"comm\": ");
						json_escape(p->comm);
						printf(", \"pid\": %d, \"uid\": %d", p->pid,
							p->uid);
						if (p->unit) {
							printf(", \"unit\": ");
							json_escape(p->unit);
						}
						printf(", \"caps\": ");
						json_escape(p->caps);
						printf(", \"defenses\": {\"runs_as_nonroot\": ");
						json_escape(p->defenses.runs_as_nonroot);
						printf(", \"no_new_privs\": ");
						json_escape(p->defenses.no_new_privs);
						printf(", \"seccomp\": ");
						json_escape(p->defenses.seccomp);
						if (p->defenses.lsm_label) {
							printf(", \"lsm\": ");
							json_escape(p->defenses.lsm_label);
						}
						if (p->defenses.securebits) {
							printf(", \"securebits\": ");
							json_escape(p->defenses.securebits);
							printf(", \"securebits_locked\": ");
							json_escape(p->defenses.securebits_locked);
						}
						printf("}, \"flags\": [");
						int firstf = 1;
						if (ep->wildcard_bind) {
							if (!firstf)
								printf(", ");
							json_escape("wildcard-bind");
							firstf = 0;
						}
						if (ep->loopback_only) {
							if (!firstf)
								printf(", ");
							json_escape("loopback-only");
							firstf = 0;
						}
						if (p->has_privileged_caps) {
							if (!firstf)
								printf(", ");
							json_escape("privileged-caps");
							firstf = 0;
						}
						if (p->securebits_locked) {
							if (!firstf)
								printf(", ");
							json_escape("securebits-locked");
						}
						printf("]}");
						if (pi + 1 != ep->procs_n)
							puts(",");
						else
							putchar('\n');
					}
					puts("          ]}");
				}
				puts("        ]}");
			}
			puts("      ]}");
		}
		puts("    ]}");
		if (i != 3)
			puts(",");
	}
	puts("  ]");
	puts("}");
}

/*
 * free_process - free one process_info and all owned dynamic fields.
 * @p: process entry pointer, or NULL.
 *
 * Returns no value.
 */
static void free_process(struct process_info *p)
{
	if (!p)
		return;
	free(p->comm);
	free(p->unit);
	free(p->caps);
	free(p->defenses.runs_as_nonroot);
	free(p->defenses.no_new_privs);
	free(p->defenses.seccomp);
	free(p->defenses.lsm_label);
	free(p->defenses.securebits);
	free(p->defenses.securebits_locked);
	free(p);
}

/*
 * free_model - free all heap allocations referenced by @m.
 * @m: model container whose internal arrays/strings are released.
 *
 * Returns no value.
 */
static void free_model(struct model *m)
{
	size_t i, j;
	for (i = 0; i < m->ifaces_n; i++) {
		free(m->ifaces[i].name);
		for (j = 0; j < m->ifaces[i].addrs_n; j++)
			free(m->ifaces[i].addrs[j].addr);
		free(m->ifaces[i].addrs);
	}
	free(m->ifaces);
	for (i = 0; i < m->procs_n; i++)
		free_process(m->procs[i]);
	free(m->procs);
	for (i = 0; i < m->inode_n; i++)
		free(m->inode_map[i].procs);
	free(m->inode_map);
	for (i = 0; i < m->eps_n; i++) {
		free(m->eps[i].proto);
		free(m->eps[i].bind);
		free(m->eps[i].label);
		free(m->eps[i].ifname);
		free(m->eps[i].ifaddr);
		free(m->eps[i].procs);
	}
	free(m->eps);
}

/*
 * netcap_advanced_main - entry point for "netcap --advanced" mode.
 * @opts: parsed options; must be non-NULL and have @advanced set.
 *
 * Collects procfs/netlink data in current netns, prints tree/JSON report,
 * and returns 0 on success or 1 when advanced mode was not requested.
 */
int netcap_advanced_main(const struct netcap_opts *opts)
{
	struct model m;

	if (!opts || !opts->advanced)
		return 1;
	memset(&m, 0, sizeof(m));
	if (collect_interfaces(&m) != 0) {
		fprintf(stderr, "warning: failed to enumerate interfaces\n");
	}
	collect_proc_inodes(&m);
	collect_endpoints(&m);
	if (opts->json)
		render_json(&m);
	else
		render_tree(&m);
	free_model(&m);
	return 0;
}
