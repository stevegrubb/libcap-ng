# Makefile.am -- utility tests
#
# Copyright 2026 Red Hat Inc.
# All Rights Reserved.

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/src -I${top_srcdir}/utils \
	-I${top_srcdir}/utils/cap-audit

check_PROGRAMS = utils_test utility_logic_test
TESTS = $(check_PROGRAMS)

utils_test_SOURCES = utils_test.c \
	${top_srcdir}/utils/filecap-path.c \
	${top_srcdir}/utils/proc-account.c

utility_logic_test_SOURCES = utility_logic_test.c \
	${top_srcdir}/utils/pscap.c \
	${top_srcdir}/utils/netcap.c \
	${top_srcdir}/utils/proc-account.c \
	${top_srcdir}/utils/proc-llist.c \
	${top_srcdir}/utils/proc-sanitize.c
utility_logic_test_CPPFLAGS = $(AM_CPPFLAGS) -DPSCAP_NO_MAIN -DPSCAP_TEST \
	-DNETCAP_NO_MAIN -DNETCAP_TEST
utility_logic_test_LDADD = ${top_builddir}/src/libcap-ng.la
