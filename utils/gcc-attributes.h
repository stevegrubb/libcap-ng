// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Steve Grubb

#ifndef GCC_ATTRIBUTES_H
#define GCC_ATTRIBUTES_H

#include <sys/cdefs.h>

/* These macros originate in sys/cdefs.h. Stub them when unavailable. */
#ifndef __returns_nonnull
# define __returns_nonnull
#endif
#ifndef __attr_access
# define __attr_access(x)
#endif
#ifndef __attr_dealloc
# define __attr_dealloc(dealloc, argno)
#endif
#ifndef __attr_dealloc_free
# define __attr_dealloc_free
#endif
#ifndef __attribute_malloc__
# define __attribute_malloc__
#endif
#ifndef __attribute_const__
# define __attribute_const__
#endif
#ifndef __attribute_pure__
# define __attribute_pure__
#endif
#ifndef __nonnull
# define __nonnull(params)
#endif
#ifndef __wur
# define __wur
#endif

#endif
