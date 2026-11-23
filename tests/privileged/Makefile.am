# SPDX-License-Identifier: GPL-2.0-or-later
# Helpers are opt-in: neither all nor check builds or runs them.
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir)/src \
	-I$(top_srcdir)/utils -I$(top_srcdir)/utils/cap-audit \
	-I$(top_builddir)/utils/cap-audit -D_GNU_SOURCE
AM_CFLAGS = -Wall -Wextra

EXTRA_PROGRAMS = kernel_workload
kernel_workload_SOURCES = kernel_workload.c
kernel_workload_LDADD = $(top_builddir)/src/libcap-ng.la -lpthread

if BUILD_CAP_AUDIT
integration_cap_audit = yes
EXTRA_PROGRAMS += cap_audit_live
cap_audit_live_SOURCES = cap_audit_live.c
cap_audit_live_CPPFLAGS = $(AM_CPPFLAGS) $(LIBBPF_CFLAGS)
cap_audit_live_LDADD = $(LIBBPF_LIBS) -lpthread
cap_audit_live-cap_audit_live.$(OBJEXT): \
	$(top_builddir)/utils/cap-audit/cap_audit.skel.h
else
integration_cap_audit = no
endif

.PHONY: integration-helpers
integration-helpers: $(EXTRA_PROGRAMS)

EXTRA_DIST = run.py test_runner.py README.md
# Automake does not clean EXTRA_PROGRAMS automatically. Include both helpers
# even after reconfiguring without cap-audit, when its old binary may remain.
CLEANFILES = prepared.json prepare.log kernel_workload$(EXEEXT) \
	cap_audit_live$(EXEEXT)

clean-local:
	$(RM) -r __pycache__
