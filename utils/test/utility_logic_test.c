/* utility_logic_test.c -- direct tests against utility translation units
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This test links the real pscap.c and netcap.c objects with their main()
 * functions compiled out. That keeps make check close to production code
 * for utility-local helpers that are not worth moving into shared modules.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc-llist.h"

size_t wrap_to(const char *text, size_t max);
int parse_u32_hex_or_dec(const char *s, unsigned int *out);

static void fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(EXIT_FAILURE);
}

static void test_wrap_to(void)
{
	/* pscap tree output should wrap cleanly on separators when possible. */
	if (wrap_to("cap_chown, cap_setuid", 12) != 11)
		fail("wrap_to should break after comma");
	if (wrap_to("alpha beta", 7) != 6)
		fail("wrap_to should prefer spaces");
	if (wrap_to("abcdefgh", 4) != 4)
		fail("wrap_to should hard-wrap when no separator exists");
}

static void test_parse_u32_hex_or_dec(void)
{
	unsigned int out;

	/* netcap accepts decimal, 0x-prefixed hex, and some procfs hex forms. */
	if (parse_u32_hex_or_dec("123", &out) != 0 || out != 123)
		fail("decimal parse failed");
	if (parse_u32_hex_or_dec("0x10", &out) != 0 || out != 16)
		fail("hex parse with prefix failed");
	if (parse_u32_hex_or_dec("0010", &out) != 0 || out != 16)
		fail("hex parse with leading zero failed");
	if (parse_u32_hex_or_dec("G1", &out) == 0)
		fail("invalid parse should fail");
}

static void test_list_inode_iteration(void)
{
	llist list;
	lnode first = { 0 };
	lnode second = { 0 };
	lnode third = { 0 };
	lnode *cur;

	list_create(&list);

	first.inode = 99;
	first.cmd = strdup("first");
	first.capabilities = strdup("cap_net_bind_service");
	first.bounds = strdup("");
	first.ambient = strdup("");
	second.inode = 99;
	second.cmd = strdup("second");
	second.capabilities = strdup("cap_net_admin");
	second.bounds = strdup("");
	second.ambient = strdup("");
	third.inode = 100;
	third.cmd = strdup("third");
	third.capabilities = strdup("cap_sys_admin");
	third.bounds = strdup("");
	third.ambient = strdup("");

	if (!first.cmd || !first.capabilities || !first.bounds ||
	    !first.ambient || !second.cmd || !second.capabilities ||
	    !second.bounds || !second.ambient || !third.cmd ||
	    !third.capabilities || !third.bounds || !third.ambient)
		fail("allocation failed in inode iteration test");

	list_append(&list, &first);
	list_append(&list, &second);
	list_append(&list, &third);

	cur = list_find_inode(&list, 99);
	if (!cur || strcmp(cur->cmd, "first") != 0)
		fail("list_find_inode should return first matching inode");
	cur = list_next_inode(&list, 99);
	if (!cur || strcmp(cur->cmd, "second") != 0)
		fail("list_next_inode should return later matching inode");
	if (list_next_inode(&list, 99) != NULL)
		fail("list_next_inode should stop at the last match");

	list_clear(&list);
}

int main(void)
{
	test_wrap_to();
	test_parse_u32_hex_or_dec();
	test_list_inode_iteration();
	puts("Direct utility logic tests passed");
	return 0;
}
