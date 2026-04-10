/*
 * proc-account.h - Shared account name helpers for proc-based utilities
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef PROC_ACCOUNT_H
#define PROC_ACCOUNT_H

#include <stddef.h>
#include <sys/types.h>

void proc_format_account_name_from_euid(int euid, char *account,
					size_t account_len);
void netcap_update_account_cache(uid_t uid, int *last_uid,
				 const char **cached_name);

#endif
