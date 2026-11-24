// SPDX-License-Identifier: GPL-2.0-or-later
/* Unprivileged JSON escaping tests, including raw executable-name bytes. */
#include "cap_audit.h"
#include <stdlib.h>
#include <string.h>

int audit_machine;

static void check_escape(const char *input, const char *expected)
{
	char *escaped = json_escape(input);

	if (!escaped || strcmp(escaped, expected)) {
		fprintf(stderr, "JSON escaping did not match expected bytes\n");
		exit(EXIT_FAILURE);
	}
	/* Also allow a strict JSON consumer to validate this test's output. */
	printf("\"%s\"\n", escaped);
	free(escaped);
}

int main(void)
{
	check_escape(NULL, "");
	check_escape("", "");
	check_escape("/usr/bin/test", "/usr/bin/test");
	check_escape("\"\\\b\f\n\r\t\001\037",
		     "\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f");
	/* Preserve valid two-, three-, and four-byte Unicode sequences. */
	check_escape("\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80",
		     "\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80");
	check_escape("/tmp/\xff", "/tmp/\\u00ff");
	check_escape("\x80\xc2", "\\u0080\\u00c2");
	check_escape("\xe2\x82", "\\u00e2\\u0082");
	check_escape("\xf0\x9f\x98", "\\u00f0\\u009f\\u0098");
	/* Overlong, surrogate, and out-of-range encodings are malformed. */
	check_escape("\xc0\xaf", "\\u00c0\\u00af");
	check_escape("\xe0\x80\xaf", "\\u00e0\\u0080\\u00af");
	check_escape("\xed\xa0\x80", "\\u00ed\\u00a0\\u0080");
	check_escape("\xf4\x90\x80\x80",
		     "\\u00f4\\u0090\\u0080\\u0080");
	check_escape("\xe2\"\n\xc3\xa9", "\\u00e2\\\"\\n\xc3\xa9");
	/*
	 * YAML reuses these strings and forbids raw DEL, C1 controls, and
	 * U+FFFE/U+FFFF even when they are valid UTF-8. Neighbouring
	 * printable characters must still be preserved unchanged.
	 */
	check_escape("a\x7f" "b", "a\\u007fb");
	check_escape("csi-\xc2\x9b" "2J", "csi-\\u009b2J");
	check_escape("\xc2\x80\xc2\x85\xc2\x9f",
		     "\\u0080\\u0085\\u009f");
	check_escape("\xc2\xa0", "\xc2\xa0");
	check_escape("\xef\xbf\xbe\xef\xbf\xbf", "\\ufffe\\uffff");
	check_escape("\xef\xbf\xbd", "\xef\xbf\xbd");
	check_escape("\xf0\x9f\xbf\xbe", "\xf0\x9f\xbf\xbe");
	return EXIT_SUCCESS;
}
