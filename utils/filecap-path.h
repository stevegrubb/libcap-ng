/*
 * filecap-path.h - PATH parsing helpers for filecap
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef FILECAP_PATH_H
#define FILECAP_PATH_H

typedef int (*filecap_path_cb)(const char *entry, void *data);

int filecap_foreach_path(const char *path_env, filecap_path_cb cb, void *data);

#endif
