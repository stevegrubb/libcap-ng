# Makefile.am -- cap-audit tests
#
# Copyright 2026 Red Hat Inc.
# All Rights Reserved.

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/utils/cap-audit

check_PROGRAMS = cap_audit_util_test
TESTS = $(check_PROGRAMS)

cap_audit_util_test_SOURCES = cap_audit_util_test.c \
	${top_srcdir}/utils/cap-audit/classify_app.c
