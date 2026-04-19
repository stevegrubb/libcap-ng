// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef CAP_AUDIT_CLASSIFY_APP_H
#define CAP_AUDIT_CLASSIFY_APP_H

typedef enum { UNSUPPORTED, ELF, PYTHON } type_t;

type_t classify_app(const char *exe);

#endif
