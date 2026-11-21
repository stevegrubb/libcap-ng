/*
 * proc-output.c - Shared terminal output helpers for proc utilities
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "config.h"
#include <errno.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <wchar.h>
#include "proc-output.h"
#include "proc-sanitize.h"

#define PROC_COLOR_RESET	"\033[0m"

/*
 * proc_output_width - choose the output width for wrapped terminal text.
 * @none: function takes no parameters.
 *
 * Returns terminal columns from ioctl(), then $COLUMNS, else 80.
 */
int proc_output_width(void)
{
	struct winsize ws;
	const int fds[] = { STDOUT_FILENO, STDERR_FILENO, STDIN_FILENO };
	const char *env;
	char *end = NULL;
	unsigned long v;
	size_t i;

	for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
		if (ioctl(fds[i], TIOCGWINSZ, &ws) == 0 && ws.ws_col)
			return ws.ws_col;
	}

	env = getenv("COLUMNS");
	if (env) {
		errno = 0;
		v = strtoul(env, &end, 10);
		if (errno == 0 && end != env && *end == '\0' && v > 0 &&
		    v < 400)
			return (int)v;
	}
	return 80;
}

/*
 * skip_ansi_sgr - skip one ANSI SGR escape sequence.
 * @text: source string that may contain an SGR sequence at @i.
 * @i: byte offset to inspect.
 *
 * Returns the first byte after the SGR sequence, or @i when @text[@i] does
 * not start one.
 */
static int skip_ansi_sgr(const char *text, int i)
{
	if (text[i] != '\033' || text[i + 1] != '[')
		return i;
	i += 2;
	while (text[i] && text[i] != 'm')
		i++;
	if (text[i] == 'm')
		i++;
	return i;
}

/*
 * copy_sgr - copy the active ANSI SGR sequence into @dst.
 * @dst: destination buffer for the active SGR sequence.
 * @dst_sz: size of @dst in bytes.
 * @text: source string containing an SGR sequence at @i.
 * @i: byte offset to inspect.
 *
 * Returns the first byte after the SGR sequence, or @i when no sequence was
 * present. A reset sequence clears @dst.
 */
static int copy_sgr(char *dst, size_t dst_sz, const char *text, int i)
{
	int start = i;
	int end;
	size_t len;

	end = skip_ansi_sgr(text, i);
	if (end == start)
		return i;

	len = end - start;
	if (strncmp(text + start, PROC_COLOR_RESET,
		    strlen(PROC_COLOR_RESET)) == 0) {
		dst[0] = '\0';
		return end;
	}
	if (len < dst_sz) {
		memcpy(dst, text + start, len);
		dst[len] = '\0';
	}
	return end;
}

/*
 * scan_color_state - update active color while scanning a wrapped segment.
 * @text: source string containing the rendered segment.
 * @from: first byte offset in the segment.
 * @to: byte offset just past the segment.
 * @active: destination buffer holding the active SGR sequence.
 * @active_sz: size of @active in bytes.
 *
 * Returns no value. @active is updated in place for continuation lines.
 */
static void scan_color_state(const char *text, int from, int to,
			     char *active, size_t active_sz)
{
	int i;

	for (i = from; i < to && text[i]; ) {
		if (text[i] == '\033' && text[i + 1] == '[') {
			i = copy_sgr(active, active_sz, text, i);
			continue;
		}
		i++;
	}
}

/*
 * wrap_ansi - choose a wrap index for text containing ANSI SGR escapes.
 * @text: source string starting at this line.
 * @limit: maximum visible columns or fallback bytes to include.
 * @utf8: whether the current locale supplies UTF-8 column widths.
 * @columns: optional destination for the measured width before the wrap.
 *
 * Returns the byte offset where output should continue; SGR bytes do not
 * count toward @limit.
 */
static int wrap_ansi(const char *text, int limit, int utf8, int *columns)
{
	int i;
	int vis = 0;
	int break_at = 0;
	int break_vis = 0;
	int width = 0;
	size_t len = 1;

	for (i = 0; text[i]; ) {
		if (text[i] == '\033' && text[i + 1] == '[') {
			i = skip_ansi_sgr(text, i);
			continue;
		}
		if (!utf8) {
			/* Count bytes without wrapping inside a UTF-8 character. */
			len = proc_utf8_char_len((const unsigned char *)text + i);
			width = len;
		} else {
			mbstate_t state = { 0 };
			wchar_t wc;

			len = mbrtowc(&wc, text + i, MB_CUR_MAX, &state);
			if (len == (size_t)-1 || len == (size_t)-2) {
				len = 1;
				width = 1;
			} else {
				width = wcwidth(wc);
				if (width < 0)
					width = 1;
			}
		}
		if (width > limit - vis)
			break;
		if (text[i] == ' ' || text[i] == ',') {
			break_at = i + len;
			break_vis = vis + width;
		}
		i += len;
		vis += width;
	}
	if (text[i] && break_at) {
		i = break_at;
		vis = break_vis;
	} else if (text[i] && i == 0) {
		i += len;
		vis = width;
	}
	if (columns)
		*columns = vis;
	return i;
}

static int is_utf8_codeset(const char *codeset)
{
	return strcasecmp(codeset, "UTF-8") == 0 ||
	       strcasecmp(codeset, "UTF8") == 0;
}

/*
 * proc_print_wrapped - print wrapped text with separate prefixes.
 * @head: prefix used for the first output line.
 * @cont: prefix used for continuation lines.
 * @text: text to render.
 * @width: target terminal width.
 *
 * Returns no value. ANSI SGR color is preserved across wrapped lines.
 */
void proc_print_wrapped(const char *head, const char *cont, const char *text,
			int width)
{
	char active[32] = "";
	int pos = 0;
	int first = 1;
	int utf8;
	locale_t locale, previous = (locale_t)0;

	locale = newlocale(LC_CTYPE_MASK, "C.UTF-8", (locale_t)0);
	if (!locale)
		locale = newlocale(LC_CTYPE_MASK, "", (locale_t)0);
	if (locale && is_utf8_codeset(nl_langinfo_l(CODESET, locale)))
		previous = uselocale(locale);
	utf8 = previous != (locale_t)0 || is_utf8_codeset(nl_langinfo(CODESET));

	while (1) {
		const char *lead = first ? head : cont;
		int lead_len;
		int avail;
		int to;

		wrap_ansi(lead, INT_MAX, utf8, &lead_len);
		avail = width - lead_len;
		if (avail < 10)
			avail = 10;
		if (!text[pos]) {
			printf("%s\n", lead);
			break;
		}

		to = pos + wrap_ansi(text + pos, avail, utf8, NULL);
		printf("%s", lead);
		if (!first && active[0])
			fputs(active, stdout);
		printf("%.*s", to - pos, text + pos);
		scan_color_state(text, pos, to, active, sizeof(active));
		if (active[0])
			fputs(PROC_COLOR_RESET, stdout);
		putchar('\n');
		while (text[to] == ' ')
			to++;
		pos = to;
		first = 0;
		if (!text[pos])
			break;
	}
	if (locale) {
		if (previous)
			uselocale(previous);
		freelocale(locale);
	}
}

/*
 * proc_tree_print_node - print one wrapped tree node.
 * @prefix: existing tree prefix, or NULL for an unadorned root.
 * @is_last: non-zero when this node is the last sibling.
 * @txt: node text to render.
 * @width: target terminal width.
 *
 * Returns no value.
 */
void proc_tree_print_node(const char *prefix, int is_last, const char *txt,
			  int width)
{
	char *head, *cont;
	size_t size;

	if (!prefix) {
		proc_print_wrapped("", "", txt, width);
		return;
	}
	/* pscap trees have no fixed depth; do not truncate ancestor branches. */
	size = strlen(prefix) + sizeof("├─ ");
	head = malloc(size);
	cont = malloc(size);
	if (!head || !cont)
		goto out;
	snprintf(head, size, "%s%s", prefix,
		 is_last ? "└─ " : "├─ ");
	proc_tree_build_child_prefix(cont, size, prefix, is_last);
	proc_print_wrapped(head, cont, txt, width);
out:
	free(head);
	free(cont);
}

/*
 * proc_tree_build_child_prefix - extend a tree prefix for child nodes.
 * @dst: destination buffer receiving the child prefix.
 * @dst_sz: size of @dst in bytes.
 * @prefix: parent prefix to extend, or NULL for an unadorned root.
 * @parent_is_last: non-zero when the parent is the last sibling.
 *
 * Returns no value.
 */
void proc_tree_build_child_prefix(char *dst, size_t dst_sz, const char *prefix,
				  int parent_is_last)
{
	snprintf(dst, dst_sz, "%s%s", prefix ? prefix : "",
		 !prefix ? "" : parent_is_last ? "   " : "│  ");
}
