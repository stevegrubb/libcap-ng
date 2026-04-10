/* utils_test.c -- utility helper regression tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * These tests cover edge cases that were previously untested in make check:
 * PATH parsing for filecap, formatting of unknown proc owners, and netcap's
 * cached passwd lookup behavior. They are intentionally narrow and avoid
 * depending on live /proc traversal so the failure modes stay reproducible.
 */

#include "config.h"
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "filecap-path.h"
#include "proc-account.h"

struct path_list {
	char **items;
	size_t count;
	size_t cap;
};

static void fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

static int append_path(const char *entry, void *data)
{
	struct path_list *list = data;
	char **tmp;

	if (list->count == list->cap) {
		size_t new_cap = list->cap ? list->cap * 2 : 4;

		tmp = realloc(list->items, new_cap * sizeof(*tmp));
		if (tmp == NULL)
			return -1;
		list->items = tmp;
		list->cap = new_cap;
	}
	list->items[list->count] = strdup(entry);
	if (list->items[list->count] == NULL)
		return -1;
	list->count++;
	return 0;
}

static void free_path_list(struct path_list *list)
{
	size_t i;

	for (i = 0; i < list->count; i++)
		free(list->items[i]);
	free(list->items);
}

static uid_t find_missing_uid(void)
{
	uid_t uid;

	for (uid = (uid_t)INT_MAX; uid > 100000; uid--) {
		if (getpwuid(uid) == NULL)
			return uid;
	}
	fail("Failed to find an unmapped uid for cache test");
	return 0;
}

static void test_path_parser(void)
{
	static const char *expected[] = {
		".", "/usr/bin", ".", "/bin", "."
	};
	struct path_list list = { 0 };
	size_t i;

	if (filecap_foreach_path(":/usr/bin::/bin:", append_path, &list) != 0)
		fail("PATH parser failed");
	if (list.count != sizeof(expected) / sizeof(expected[0]))
		fail("PATH parser returned unexpected entry count");
	for (i = 0; i < list.count; i++) {
		if (strcmp(list.items[i], expected[i]) != 0)
			fail("PATH parser lost or reordered entries");
	}
	free_path_list(&list);
}

static void test_account_formatting(void)
{
	char account[32];
	uid_t missing_uid = find_missing_uid();
	int last_uid = 0;
	const char *cached_name = "root";

	/* Unknown proc owners should stay explicit instead of becoming root. */
	proc_format_account_name_from_euid(-1, account, sizeof(account));
	if (strcmp(account, "unknown") != 0)
		fail("Negative euid should format as unknown");

	proc_format_account_name_from_euid(0, account, sizeof(account));
	if (strcmp(account, "root") != 0)
		fail("Root euid should format as root");

	proc_format_account_name_from_euid((int)missing_uid, account,
					   sizeof(account));
	if (strcmp(account, "root") == 0 || strcmp(account, "unknown") == 0)
		fail("Missing passwd entry should fall back to numeric uid");

	/* A failed lookup must not leave the previous cached name in place. */
	netcap_update_account_cache(missing_uid, &last_uid, &cached_name);
	if (cached_name != NULL)
		fail("Missing passwd entry should clear stale cached name");
	if (last_uid != (int)missing_uid)
		fail("Missing passwd entry should update last_uid");
}

int main(void)
{
	test_path_parser();
	test_account_formatting();
	puts("Utility helper tests passed");
	return 0;
}
