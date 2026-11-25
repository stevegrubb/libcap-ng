/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* change_id_transition_test.c -- unprivileged credential transition tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 */

#include "config.h"
#include "../cap-ng.h"
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

static struct __user_cap_data_struct current_caps[2];
static unsigned int group_calls;
static size_t group_count;
static unsigned int uid_calls;
static int keepcaps;
/* Simulated kernel bounding set; drops require effective CAP_SETPCAP. */
static uint64_t kernel_bounds = ~0ULL;
static unsigned int nnp_calls;
static int nnp_error;
static __u32 final_effective;
static gid_t expected_gid = 7;
/* Credential step forced to fail; FAIL_NONE lets every step succeed. */
static enum {
	FAIL_NONE, FAIL_SETRESGID, FAIL_SETGROUPS, FAIL_SETRESUID,
} fail_at;
static struct {
	unsigned int calls;
	unsigned int retries;
	size_t previous_size;
	int error;
	int missing;
} lookup;

/*
 * check - require a transition invariant.
 * @condition: nonzero when the invariant holds.
 * @message: diagnostic on failure.
 *
 * Returns no value; terminates the test on failure.
 */
static void check(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "%s\n", message);
		exit(EXIT_FAILURE);
	}
}

/*
 * capget - provide a fixed capability ABI and simulated process state.
 * @header: requested ABI, updated during version discovery.
 * @data: destination capability words, or NULL for discovery.
 *
 * Returns 0 on a read, -1 with EINVAL for version discovery.
 */
int capget(cap_user_header_t header, const cap_user_data_t data)
{
	header->version = _LINUX_CAPABILITY_VERSION_3;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	memcpy(data, current_caps, sizeof(current_caps));
	return 0;
}

/*
 * capset - enforce the capability subset rules relevant to this test.
 * @header: capability ABI selected by the library.
 * @data: requested process capabilities.
 *
 * Returns 0 on success, -1 if effective exceeds permitted or permitted grows.
 * No kernel credentials are changed by this test executable.
 */
int capset(cap_user_header_t header, cap_user_data_t data)
{
	size_t i;

	check(header->version == _LINUX_CAPABILITY_VERSION_3,
	      "Unexpected capability ABI");
	for (i = 0; i < 2; i++) {
		if ((data[i].effective & ~data[i].permitted) ||
		    (data[i].permitted & ~current_caps[i].permitted)) {
			errno = EPERM;
			return -1;
		}
	}
	memcpy(current_caps, data, sizeof(current_caps));
	return 0;
}

/*
 * prctl - allow keepcaps without touching the running test's credentials.
 * @option: requested operation; optional arguments are unused.
 *
 * Returns 0 for keepcaps, -1 with EINVAL for unrelated feature probes.
 */
int prctl(int option, ...)
{
	if (option == PR_SET_KEEPCAPS) {
		va_list ap;

		va_start(ap, option);
		keepcaps = va_arg(ap, int);
		va_end(ap);
		return 0;
	}
	if (option == PR_SET_NO_NEW_PRIVS) {
		/* It must follow every credential and capability change. */
		check(uid_calls == 1 && !keepcaps &&
		      current_caps[0].effective == final_effective &&
		      !(current_caps[0].permitted &
			((1U << CAP_SETUID) | (1U << CAP_SETGID))),
		      "NoNewPrivileges was set before the transition settled");
		nnp_calls++;
		if (nnp_error) {
			errno = nnp_error;
			return -1;
		}
		return 0;
	}
	if (option == PR_CAPBSET_READ || option == PR_CAPBSET_DROP) {
		va_list ap;
		unsigned long capability;

		va_start(ap, option);
		capability = va_arg(ap, unsigned long);
		va_end(ap);
		if (capability >= 64) {
			errno = EINVAL;
			return -1;
		}
		if (option == PR_CAPBSET_READ)
			return (kernel_bounds >> capability) & 1;
		if (!(current_caps[0].effective & (1U << CAP_SETPCAP))) {
			errno = EPERM;
			return -1;
		}
		kernel_bounds &= ~(1ULL << capability);
		return 0;
	}
	if (option == PR_CAP_AMBIENT) {
		va_list ap;
		int op;

		va_start(ap, option);
		op = va_arg(ap, int);
		va_end(ap);
		/* Report an empty ambient set and accept clearing it. */
		if (op == PR_CAP_AMBIENT_IS_SET || op == PR_CAP_AMBIENT_CLEAR_ALL)
			return 0;
	}
	errno = EINVAL;
	return -1;
}

/*
 * setgroups - check transition-time SETGID without changing real groups.
 * @count: number of requested groups.
 * @groups: requested group IDs.
 *
 * Returns 0 with effective SETGID, -1 with EPERM otherwise.
 */
int setgroups(size_t count, const gid_t *groups)
{
	check((count == 0 && groups == NULL) ||
	      (count > 0 && groups != NULL), "Invalid supplementary groups");
	group_calls++;
	if (fail_at == FAIL_SETGROUPS) {
		errno = EPERM;
		return -1;
	}
	if (current_caps[0].effective & (1U << CAP_SETGID)) {
		group_count = count;
		return 0;
	}
	errno = EPERM;
	return -1;
}

/*
 * getpwuid - poison shared passwd storage to reject non-reentrant lookups.
 * @uid: target user ID.
 *
 * Returns another account's fields, as if an intervening lookup overwrote
 * the shared result. Only caller-owned getpwuid_r storage is stable.
 */
struct passwd *getpwuid(uid_t uid)
{
	static struct passwd account = {
		.pw_name = "other-account", .pw_uid = 42, .pw_gid = 0,
	};

	check(uid == account.pw_uid, "Unexpected user lookup");
	return &account;
}

/*
 * getpwuid_r - resolve a synthetic account into caller-owned storage.
 * @uid: target user ID.
 * @pw: destination account record.
 * @buf: destination for account strings.
 * @size: buffer capacity.
 * @result: resolved record, or NULL when absent.
 *
 * Returns a configured error or account, exercising buffer growth and
 * missing users without relying on local NSS data. The five parameters
 * are required by the libc interface being interposed.
 */
int getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t size,
	      struct passwd **result)
{
	check(uid == 42, "Unexpected reentrant user lookup");
	check(size > lookup.previous_size, "Lookup buffer did not grow");
	lookup.previous_size = size;
	lookup.calls++;
	*result = NULL;
	if (lookup.calls <= lookup.retries)
		return ERANGE;
	if (lookup.error || lookup.missing)
		return lookup.error;
	check(size >= sizeof("transition-test"), "Lookup buffer too small");
	memset(pw, 0, sizeof(*pw));
	strcpy(buf, "transition-test");
	pw->pw_name = buf;
	pw->pw_uid = uid;
	pw->pw_gid = 7;
	*result = pw;
	return 0;
}

/*
 * getgrouplist - supply one natural group for the synthetic account.
 * @user: account name.
 * @gid: primary group to include.
 * @groups: output group array.
 * @count: capacity on input, group count on output.
 *
 * Returns 1; the library supplies space for at least one group.
 */
int getgrouplist(const char *user, gid_t gid, gid_t *groups, int *count)
{
	check(!strcmp(user, "transition-test") && gid == expected_gid &&
	      *count >= 1,
	      "Unexpected group lookup");
	groups[0] = gid;
	*count = 1;
	return 1;
}

/*
 * initgroups - exercise the same SETGID check as staged group application.
 * @user: account name.
 * @gid: natural primary group.
 *
 * Returns the simulated setgroups result.
 */
int initgroups(const char *user, gid_t gid)
{
	check(!strcmp(user, "transition-test") && gid == expected_gid,
	      "Unexpected initgroups account");
	return setgroups(1, &gid);
}

/*
 * setresgid - accept the explicit primary group without changing real IDs.
 * @real: requested real GID.
 * @effective: requested effective GID.
 * @saved: requested saved GID.
 *
 * Returns 0 after checking the expected primary group override.
 */
int setresgid(gid_t real, gid_t effective, gid_t saved)
{
	check(real == expected_gid && effective == real && saved == real,
	      "Unexpected group transition");
	if (fail_at == FAIL_SETRESGID) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * setresuid - verify SETUID is available without changing real user IDs.
 * @real: requested real UID.
 * @effective: requested effective UID.
 * @saved: requested saved UID.
 *
 * Returns 0; unexpected IDs or missing SETUID fail the test.
 */
int setresuid(uid_t real, uid_t effective, uid_t saved)
{
	uid_calls++;
	check(real == 42 && effective == 42 && saved == 42,
	      "Unexpected user transition");
	check(current_caps[0].effective & (1U << CAP_SETUID),
	      "Missing temporary SETUID");
	if (fail_at == FAIL_SETRESUID) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * prepare_transition - reset the simulated credentials and lookup state.
 *
 * Returns no value; stages an empty final capability set.
 */
static void prepare_transition(void)
{
	memset(current_caps, 0, sizeof(current_caps));
	current_caps[0].effective = (1U << CAP_SETGID) | (1U << CAP_SETUID);
	current_caps[0].permitted = current_caps[0].effective;
	memset(&lookup, 0, sizeof(lookup));
	group_calls = uid_calls = 0;
	group_count = 2;
	capng_clear(CAPNG_SELECT_ALL);
}

/*
 * test_drop_precedence - require DROP to suppress INIT in every ID mode.
 *
 * Returns no value; checks that a new gid clears supplementary groups,
 * gid == -1 preserves them, and neither case resolves the target account.
 */
static void test_drop_precedence(void)
{
	int init, change_uid, change_gid;

	for (init = 0; init <= 1; init++) {
		for (change_uid = 1; change_uid >= 0; change_uid--) {
			for (change_gid = 1; change_gid >= 0; change_gid--) {
				capng_flags_t flags = CAPNG_DROP_SUPP_GRP;

				prepare_transition();
				expected_gid = 9;
				if (init)
					flags |= CAPNG_INIT_SUPP_GRP;
				/* An ignored INIT must not need SETGID either. */
				if (!change_gid) {
					current_caps[0].effective &=
						~(1U << CAP_SETGID);
					current_caps[0].permitted &=
						~(1U << CAP_SETGID);
				}
				check(capng_change_id(change_uid ? 42 : -1,
						     change_gid ? 9 : -1, flags) == 0,
				      "Supplementary group drop failed");
				check(group_calls == (unsigned int)change_gid &&
				      group_count == (change_gid ? 0 : 2),
				      "DROP did not control supplementary groups");
				check(lookup.calls == 0,
				      "DROP performed an unnecessary account lookup");
				check(uid_calls == (unsigned int)change_uid &&
				      !keepcaps,
				      "Incorrect drop transition cleanup");
				check(current_caps[0].effective == 0 &&
				      current_caps[0].permitted == 0,
				      "Drop retained temporary capabilities");
			}
		}
	}
}

/*
 * test_account_lookup - exercise private lookup storage and failure cleanup.
 *
 * Returns no value; checks both natural-group modes with a default or explicit
 * primary group, repeated ERANGE, missing accounts, and lookup errors.
 */
static void test_account_lookup(void)
{
	int merged, explicit_gid, outcome;
	gid_t group = 8;

	for (merged = 0; merged <= 1; merged++) {
		for (explicit_gid = 0; explicit_gid <= 1; explicit_gid++) {
			for (outcome = 0; outcome < 4; outcome++) {
				capng_flags_t flags = CAPNG_INIT_SUPP_GRP;
				int rc;

				prepare_transition();
				expected_gid = explicit_gid ? 9 : 7;
				lookup.retries = outcome == 1 ? 2 : 0;
				lookup.missing = outcome == 2;
				lookup.error = outcome == 3 ? EIO : 0;
				if (merged) {
					flags |= CAPNG_APPLY_STAGED_GROUPS;
					check(capng_stage_additional_groups(&group, 1)
					      == 0, "Failed to stage lookup groups");
				}
				rc = capng_change_id(42, explicit_gid ? 9 : -1,
						     flags);
				check(rc == (outcome >= 2 ? -10 : 0),
				      "Unexpected account lookup result");
				check(lookup.calls == lookup.retries + 1,
				      "Unexpected account lookup count");
				check(group_calls == (outcome < 2) &&
				      uid_calls == (outcome < 2) && !keepcaps,
				      "Incorrect lookup failure cleanup");
				check(capng_change_id(-1, -1,
						CAPNG_APPLY_STAGED_GROUPS) == -13,
				      "Lookup retained staged groups");
			}
		}
	}
}

/*
 * test_failure_restores_staged_caps - keep failed transitions out of state.
 *
 * Returns no value; checks that a failure at each credential step leaves
 * no temporary SETUID or SETGID bit staged, while a SETGID bit the caller
 * requested survives, so a later capng_apply() cannot grant extra caps.
 */
static void test_failure_restores_staged_caps(void)
{
	static const struct {
		int point;
		int expected;
	} cases[] = {
		{ FAIL_SETRESGID, -4 },
		{ FAIL_SETGROUPS, -5 },
		{ FAIL_SETRESUID, -6 },
	};
	size_t i;
	int retain;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (retain = 0; retain <= 1; retain++) {
			prepare_transition();
			expected_gid = 9;
			if (retain)
				check(capng_update(CAPNG_ADD, CAPNG_PERMITTED,
						   CAP_SETGID) == 0,
				      "Failed to stage permitted-only SETGID");
			fail_at = cases[i].point;
			check(capng_change_id(42, 9, CAPNG_INIT_SUPP_GRP) ==
			      cases[i].expected,
			      "Unexpected credential failure result");
			fail_at = FAIL_NONE;
			check(!keepcaps, "Failure left keepcaps enabled");
			check(!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETUID) &&
			      !capng_have_capability(CAPNG_PERMITTED, CAP_SETUID) &&
			      !capng_have_capability(CAPNG_EFFECTIVE, CAP_SETGID),
			      "Failure left temporary capabilities staged");
			check(capng_have_capability(CAPNG_PERMITTED, CAP_SETGID) ==
			      retain,
			      "Failure changed a requested capability");
		}
	}
}

/*
 * test_bounding_transition - change the bounding set during a transition.
 *
 * Returns no value; checks that CAPNG_CLEAR_BOUNDING drops every bit using
 * a temporary CAP_SETPCAP that does not survive, that a missing SETPCAP
 * fails before credentials change, and that CAPNG_APPLY_BOUNDING installs
 * exactly the staged set.
 */
static void test_bounding_transition(void)
{
	prepare_transition();
	expected_gid = 9;
	kernel_bounds = ~0ULL;
	current_caps[0].effective |= 1U << CAP_SETPCAP;
	current_caps[0].permitted |= 1U << CAP_SETPCAP;
	check(capng_change_id(42, 9, CAPNG_CLEAR_BOUNDING) == 0,
	      "Transition clearing the bounding set failed");
	check(!(kernel_bounds & ((1ULL << (capng_last_cap() + 1)) - 1)),
	      "Bounding set was not cleared");
	check(current_caps[0].effective == 0 && current_caps[0].permitted == 0,
	      "Temporary SETPCAP survived the bounding transition");

	/* Without SETPCAP to borrow, fail before changing credentials. */
	prepare_transition();
	expected_gid = 9;
	kernel_bounds = ~0ULL;
	check(capng_change_id(42, 9, CAPNG_CLEAR_BOUNDING) == -3 &&
	      uid_calls == 0 && kernel_bounds == ~0ULL,
	      "Bounding transition without SETPCAP was not refused");
	check(!capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP),
	      "Refused bounding transition left SETPCAP staged");

	prepare_transition();
	expected_gid = 9;
	kernel_bounds = ~0ULL;
	current_caps[0].effective |= 1U << CAP_SETPCAP;
	current_caps[0].permitted |= 1U << CAP_SETPCAP;
	capng_clear(CAPNG_SELECT_BOUNDS);
	check(capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, CAP_NET_BIND_SERVICE)
	      == 0, "Cannot stage the bounding set");
	check(capng_change_id(42, 9, CAPNG_APPLY_BOUNDING) == 0,
	      "Transition applying the bounding set failed");
	check((kernel_bounds & ((1ULL << (capng_last_cap() + 1)) - 1)) ==
	      1ULL << CAP_NET_BIND_SERVICE,
	      "Staged bounding set was not applied exactly");
	kernel_bounds = ~0ULL;
}

/*
 * test_no_new_privs - CAPNG_SET_NO_NEW_PRIVS is the final transition step.
 *
 * Returns no value; checks that the flag requests no_new_privs once after
 * the final sets are installed, that it is not requested without the flag
 * or after an earlier failure, and that its own failure returns -18.
 */
static void test_no_new_privs(void)
{
	int with_flag;

	for (with_flag = 0; with_flag <= 1; with_flag++) {
		prepare_transition();
		expected_gid = 9;
		nnp_calls = 0;
		final_effective = 0;
		check(capng_change_id(42, 9, CAPNG_DROP_SUPP_GRP |
				     (with_flag ? CAPNG_SET_NO_NEW_PRIVS : 0)) == 0,
		      "Transition with no_new_privs failed");
		check(nnp_calls == (unsigned int)with_flag,
		      "no_new_privs request did not follow the flag");
	}

	prepare_transition();
	expected_gid = 9;
	nnp_calls = 0;
	fail_at = FAIL_SETRESUID;
	check(capng_change_id(42, 9, CAPNG_SET_NO_NEW_PRIVS) == -6,
	      "Unexpected result for a failed transition");
	fail_at = FAIL_NONE;
	check(nnp_calls == 0, "no_new_privs was set after a failed transition");

	prepare_transition();
	expected_gid = 9;
	nnp_calls = 0;
	nnp_error = EPERM;
	check(capng_change_id(42, 9, CAPNG_SET_NO_NEW_PRIVS) == -18 &&
	      nnp_calls == 1,
	      "A failed no_new_privs request was not reported");
	nnp_error = 0;
}

/*
 * main - verify group-only transitions and exact final SETGID preservation.
 *
 * Returns success only when each mode works without real process privileges.
 */
int main(void)
{
	const capng_flags_t modes[] = {
		CAPNG_APPLY_STAGED_GROUPS,
		CAPNG_INIT_SUPP_GRP,
		CAPNG_INIT_SUPP_GRP | CAPNG_APPLY_STAGED_GROUPS,
	};
	gid_t group = 8;
	size_t i;
	int retain;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		for (retain = 0; retain <= 1; retain++) {
			prepare_transition();
			if (retain)
				check(capng_update(CAPNG_ADD, CAPNG_PERMITTED,
						   CAP_SETGID) == 0,
				      "Failed to stage permitted-only SETGID");
			if (modes[i] & CAPNG_APPLY_STAGED_GROUPS)
				check(capng_stage_additional_groups(&group, 1) == 0,
				      "Failed to stage groups");
			check(capng_change_id(i == 0 ? -1 : 42, -1, modes[i]) == 0,
			      "Group-only transition failed");
			check(group_calls == 1, "Groups were not applied once");
			check(current_caps[0].effective == 0 &&
			      current_caps[0].permitted ==
				(retain ? 1U << CAP_SETGID : 0),
			      "Temporary capabilities changed the final request");
			check(capng_change_id(-1, -1,
					     CAPNG_APPLY_STAGED_GROUPS) == -13,
			      "Staged groups were not consumed");
		}
	}
	test_account_lookup();
	test_drop_precedence();
	test_failure_restores_staged_caps();
	test_no_new_privs();
	test_bounding_transition();
	return EXIT_SUCCESS;
}
