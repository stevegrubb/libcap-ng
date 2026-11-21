# SPDX-License-Identifier: GPL-2.0-or-later
# Makefile.am -- utility tests
#
# Copyright 2026 Red Hat Inc.
# All Rights Reserved.

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/src -I${top_srcdir}/utils \
	-I${top_srcdir}/utils/cap-audit

EXTRA_DIST = netcap_json_test.py

check_PROGRAMS = utils_test utility_logic_test pscap_test filecap_test
TESTS = $(check_PROGRAMS)

utils_test_SOURCES = utils_test.c \
	${top_srcdir}/utils/filecap-path.c \
	${top_srcdir}/utils/proc-account.c \
	${top_srcdir}/utils/proc-status.c

utility_logic_test_SOURCES = utility_logic_test.c \
	${top_srcdir}/utils/netcap.c \
	${top_srcdir}/utils/proc-account.c \
	${top_srcdir}/utils/proc-llist.c \
	${top_srcdir}/utils/proc-output.c \
	${top_srcdir}/utils/proc-sanitize.c
utility_logic_test_CPPFLAGS = $(AM_CPPFLAGS) -DNETCAP_NO_MAIN -DNETCAP_TEST
utility_logic_test_LDFLAGS = -Wl,--wrap=newlocale
utility_logic_test_LDADD = ${top_builddir}/src/libcap-ng.la

pscap_test_SOURCES = pscap_test.c \
	${top_srcdir}/utils/proc-account.c \
	${top_srcdir}/utils/proc-output.c \
	${top_srcdir}/utils/proc-sanitize.c \
	${top_srcdir}/utils/proc-status.c
pscap_test_CPPFLAGS = $(AM_CPPFLAGS) -D_GNU_SOURCE
pscap_test_LDADD = ${top_builddir}/src/libcap-ng.la

filecap_test_SOURCES = filecap_test.c \
	${top_srcdir}/utils/filecap-path.c \
	${top_srcdir}/utils/proc-sanitize.c
filecap_test_CPPFLAGS = $(AM_CPPFLAGS) -D_GNU_SOURCE
filecap_test_LDADD = ${top_builddir}/src/libcap-ng.la

if BUILD_NETCAP_ADVANCED
check_PROGRAMS += netcap_advanced_test
netcap_advanced_test_SOURCES = netcap_advanced_test.c \
	${top_srcdir}/utils/proc-output.c \
	${top_srcdir}/utils/proc-sanitize.c \
	${top_srcdir}/utils/proc-status.c
netcap_advanced_test_CPPFLAGS = $(AM_CPPFLAGS) -D_GNU_SOURCE
netcap_advanced_test_LDFLAGS = -Wl,--wrap=capng_get_caps_process
netcap_advanced_test_LDADD = ${top_builddir}/src/libcap-ng.la
if USE_PYTHON3
TESTS += netcap_json_test.py
endif
endif
