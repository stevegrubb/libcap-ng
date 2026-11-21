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
 * proc_utf8_sequence_length - validate one UTF-8 character.
 * @s: first byte of the candidate sequence.
 * @remaining: readable bytes starting at @s.
 *
 * Returns the sequence length, or zero for a truncated, overlong, surrogate,
 * out-of-range, or otherwise malformed encoding.
 */
size_t proc_utf8_sequence_length(const unsigned char *s, size_t remaining)
{
	unsigned char c;

	if (remaining == 0)
		return 0;
	c = s[0];

	if (c < 0x80)
		return 1;
	if (c >= 0xc2 && c <= 0xdf)
		return remaining >= 2 && s[1] >= 0x80 && s[1] <= 0xbf ?
			2 : 0;
	if (c >= 0xe0 && c <= 0xef) {
		if (remaining < 3 || s[2] < 0x80 || s[2] > 0xbf)
			return 0;
		if (c == 0xe0)
			return s[1] >= 0xa0 && s[1] <= 0xbf ? 3 : 0;
		if (c == 0xed)
			return s[1] >= 0x80 && s[1] <= 0x9f ? 3 : 0;
		return s[1] >= 0x80 && s[1] <= 0xbf ? 3 : 0;
	}
	if (c >= 0xf0 && c <= 0xf4) {
		if (remaining < 4 || s[2] < 0x80 || s[2] > 0xbf ||
		    s[3] < 0x80 || s[3] > 0xbf)
			return 0;
		if (c == 0xf0)
			return s[1] >= 0x90 && s[1] <= 0xbf ? 4 : 0;
		if (c == 0xf4)
			return s[1] >= 0x80 && s[1] <= 0x8f ? 4 : 0;
		return s[1] >= 0x80 && s[1] <= 0xbf ? 4 : 0;
	}
	return 0;
}

/*
 * sanitize_untrusted_field - escape terminal control bytes in untrusted text.
 * @src: source text gathered from procfs/cgroup metadata.
 *
 * Returns caller-owned sanitized text, or NULL on allocation failure.
 * Side effects/assumptions: Operates on in-memory data and may read
 * procfs/netns state; it does not change kernel configuration.
 */
char *sanitize_untrusted_field(const char *src)
{
	size_t in_len;
	char *dst;
	char *out;
	size_t i;

	if (!src)
		return NULL;
	in_len = strlen(src);
	dst = malloc(in_len * 4 + 1);
	if (!dst)
		return NULL;
	out = dst;
	for (i = 0; i < in_len; ) {
		unsigned char c = (unsigned char)src[i];
		size_t seq_len = proc_utf8_sequence_length(
			(const unsigned char *)&src[i], in_len - i);
		size_t j;

		/* Do not leave a C1 byte inside an otherwise valid UTF-8 sequence:
		 * an 8-bit terminal could still interpret that byte as a control.
		 * Escape the whole sequence so the display is not left with a
		 * partial, invalid character. Other UTF-8 remains unchanged.
		 */
		if (seq_len > 1) {
			int escape_sequence = 0;

			for (j = 0; j < seq_len; j++) {
				unsigned char byte = (unsigned char)src[i + j];

				if (byte >= 0x80 && byte <= 0x9f) {
					escape_sequence = 1;
					break;
				}
			}
			if (escape_sequence) {
				for (j = 0; j < seq_len; j++) {
					snprintf(out, 5, "\\x%02X",
						 (unsigned char)src[i + j]);
					out += 4;
				}
			} else {
				memcpy(out, &src[i], seq_len);
				out += seq_len;
			}
			i += seq_len;
			continue;
		}
		if (c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f)) {
			snprintf(out, 5, "\\x%02X", c);
			out += 4;
		} else {
			*out++ = (char)c;
		}
		i++;
	}
	*out = '\0';
	return dst;
}

/*
 * sanitize_untrusted_owned - replace owned string with sanitized version.
 * @s: pointer to owned string pointer that will be replaced in place.
 *
 * Returns 0 on success, -1 on allocation failure.
 * Side effects/assumptions: Operates on in-memory data and may read
 * procfs/netns state; it does not change kernel configuration.
 */
int sanitize_untrusted_owned(char **s)
{
	char *safe;

	if (!s || !*s)
		return 0;
	safe = sanitize_untrusted_field(*s);
	if (!safe)
		return -1;
	free(*s);
	*s = safe;
	return 0;
}
