/*
 * proc-account.c - Shared account name helpers for proc-based utilities
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * pscap and netcap used to each carry their own owner-formatting logic.
 * The helpers live here so the reporting policy stays consistent and so
 * make check can cover the failure cases directly. In particular, unknown
 * proc owners must never be rewritten as "root", and a failed passwd
 * lookup must not leak a stale cached username into later rows.
 */

#include "config.h"
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include "proc-account.h"

void proc_format_account_name_from_euid(int euid, char *account,
					size_t account_len)
{
	struct passwd *p;

	if (euid < 0) {
		strncpy(account, "unknown", account_len - 1);
		account[account_len - 1] = '\0';
		return;
	}
	if (euid == 0) {
		strncpy(account, "root", account_len - 1);
		account[account_len - 1] = '\0';
		return;
	}

	p = getpwuid(euid);
	if (p && p->pw_name) {
		strncpy(account, p->pw_name, account_len - 1);
		account[account_len - 1] = '\0';
		return;
	}

	snprintf(account, account_len, "%d", euid);
}

void netcap_update_account_cache(uid_t uid, int *last_uid,
				 const char **cached_name)
{
	struct passwd *p;

	if (uid == 0) {
		*cached_name = "root";
		*last_uid = 0;
		return;
	}
	if (uid == (uid_t)-1) {
		*cached_name = "unknown";
		*last_uid = -1;
		return;
	}
	if (*last_uid == (int)uid)
		return;

	/*
	 * Clear the cached pointer before looking up the next uid so a failed
	 * passwd lookup cannot leak the previous account name into output.
	 */
	*cached_name = NULL;
	p = getpwuid(uid);
	*last_uid = uid;
	if (p)
		*cached_name = p->pw_name;
}
