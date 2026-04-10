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

int main(void)
{
	test_wrap_to();
	test_parse_u32_hex_or_dec();
	puts("Direct utility logic tests passed");
	return 0;
}
