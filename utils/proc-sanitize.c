/*
 * proc-sanitize.c - Shared terminal sanitization helpers for proc text
 * Copyright (c) 2026 Steve Grubb
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc-sanitize.h"

/*
 * Read one character from a NUL-terminated string. A malformed or truncated
 * sequence consumes one byte so each caller can apply its own output policy.
 */
size_t proc_utf8_char_len(const unsigned char *s)
{
	size_t len, i;

	if (s[0] < 0xc2 || s[0] > 0xf4 || s[1] < 0x80 || s[1] > 0xbf)
		return 1;
	if (s[0] <= 0xdf)
		return 2;
	/* Reject overlong encodings, surrogates, and values above U+10FFFF. */
	if ((s[0] == 0xe0 && s[1] < 0xa0) || (s[0] == 0xed && s[1] >= 0xa0) ||
	    (s[0] == 0xf0 && s[1] < 0x90) || (s[0] == 0xf4 && s[1] >= 0x90))
		return 1;
	len = s[0] <= 0xef ? 3 : 4;
	for (i = 2; i < len; i++)
		if (s[i] < 0x80 || s[i] > 0xbf)
			return 1;
	return len;
}

/*
 * sanitize_untrusted_field - escape terminal control bytes in untrusted text.
 * @src: NUL-terminated metadata or pathname, or NULL.
 *
 * Returns caller-owned sanitized text, or NULL for NULL input or allocation
 * failure.
 */
char *sanitize_untrusted_field(const char *src)
{
	const unsigned char *p = (const unsigned char *)src;
	char *dst, *out;

	if (!src)
		return NULL;
	dst = malloc(strlen(src) * 4 + 1);
	if (!dst)
		return NULL;
	out = dst;
	while (*p) {
		size_t len = proc_utf8_char_len(p);
		size_t i;

		/* An 8-bit terminal may interpret a C1 byte even inside valid
		 * UTF-8. Escape the whole character to avoid a partial glyph.
		 */
		for (i = 0; i < len; i++)
			if (p[i] < 0x20 || (p[i] >= 0x7f && p[i] <= 0x9f))
				break;
		if (i == len) {
			memcpy(out, p, len);
			out += len;
		} else {
			for (i = 0; i < len; i++) {
				snprintf(out, 5, "\\x%02X", p[i]);
				out += 4;
			}
		}
		p += len;
	}
	*out = '\0';
	return dst;
}
