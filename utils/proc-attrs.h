/*
 * proc-attrs.h - glibc-style attribute helpers for proc utilities
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#ifndef PROC_ATTRS_H
#define PROC_ATTRS_H

#include <sys/cdefs.h>

/* sys/cdefs.h provides this on glibc; other libcs may not. */
#ifndef __attr_access
# define __attr_access(x)
#endif

#endif
