// SPDX-License-Identifier: GPL-2.0-or-later
/* Observation health shared by human and machine report decisions. */
#include "cap_audit.h"

#include <sys/wait.h>

const char *audit_stop_reason(void)
{
	switch (state.observation.stop_reason) {
	case TRACE_STOP_TARGET_EXIT:
		return "target_exit";
	case TRACE_STOP_REQUESTED:
		return "requested_stop";
	case TRACE_STOP_POLL_ERROR:
		return "poll_error";
	case TRACE_STOP_WAIT_ERROR:
		return "wait_error";
	default:
		return "unknown";
	}
}

const char *audit_collection_reason(void)
{
	const struct observation_status *s = &state.observation;

	if (s->launch_error)
		return "target_launch_failed";
	if (!s->exec_confirmed)
		return "target_exec_unconfirmed";
	if (s->stop_reason != TRACE_STOP_TARGET_EXIT || !s->target_exited)
		return audit_stop_reason();
	if (s->descendants_remaining)
		return "descendants_remaining";
	if (s->map_failures || s->ring_failures || s->capset_read_failures ||
	    s->userspace_failures)
		return "observations_lost";
	return NULL;
}

void output_observation_json(void)
{
	const struct observation_status *s = &state.observation;

	printf("  \"schema_version\": 1,\n");
	printf("  \"recommendations_eligible\": %s,\n",
	       audit_recommendation_reason() ? "false" : "true");
	printf("  \"recommendation_block_reason\": ");
	if (audit_recommendation_reason())
		printf("\"%s\"", audit_recommendation_reason());
	else
		printf("null");
	printf(",\n  \"namespace_scope\": \"%s\",\n", audit_namespace_scope());
	printf("  \"baseline_user_namespace\": %u,\n",
	       state.baseline_user_ns_inum);
	printf("  \"observation\": {\n");
	printf("    \"collection_complete\": %s,\n",
	       audit_collection_reason() ? "false" : "true");
	printf("    \"stop_reason\": \"%s\",\n", audit_stop_reason());
	printf("    \"target_exec_confirmed\": %s,\n",
	       s->exec_confirmed ? "true" : "false");
	printf("    \"launch_error\": %d,\n", s->launch_error);
	printf("    \"target_exit_status\": ");
	if (s->target_exited && WIFEXITED(s->wait_status))
		printf("%d", WEXITSTATUS(s->wait_status));
	else
		printf("null");
	printf(",\n    \"target_signal\": ");
	if (s->target_exited && WIFSIGNALED(s->wait_status))
		printf("%d", WTERMSIG(s->wait_status));
	else
		printf("null");
	printf(",\n    \"descendants_remaining\": %s,\n",
	       s->descendants_remaining ? "true" : "false");
	printf("    \"descendants_followed\": %s,\n",
	       s->descendants_followed ? "true" : "false");
	printf("    \"map_update_failures\": %llu,\n",
	       (unsigned long long)s->map_failures);
	printf("    \"ring_reservation_failures\": %llu,\n",
	       (unsigned long long)s->ring_failures);
	printf("    \"capset_read_failures\": %llu,\n",
	       (unsigned long long)s->capset_read_failures);
	printf("    \"userspace_failures\": %lu\n", s->userspace_failures);
	printf("  },\n");
}

void output_observation_yaml(void)
{
	const struct observation_status *s = &state.observation;

	printf("schema_version: 1\n");
	printf("recommendations_eligible: %s\n",
	       audit_recommendation_reason() ? "false" : "true");
	printf("recommendation_block_reason: %s\n",
	       audit_recommendation_reason() ?: "null");
	printf("namespace_scope: %s\n", audit_namespace_scope());
	printf("baseline_user_namespace: %u\n", state.baseline_user_ns_inum);
	printf("observation:\n");
	printf("  collection_complete: %s\n",
	       audit_collection_reason() ? "false" : "true");
	printf("  stop_reason: %s\n", audit_stop_reason());
	printf("  target_exec_confirmed: %s\n",
	       s->exec_confirmed ? "true" : "false");
	printf("  launch_error: %d\n", s->launch_error);
	printf("  target_exit_status: ");
	if (s->target_exited && WIFEXITED(s->wait_status))
		printf("%d\n", WEXITSTATUS(s->wait_status));
	else
		printf("null\n");
	printf("  target_signal: ");
	if (s->target_exited && WIFSIGNALED(s->wait_status))
		printf("%d\n", WTERMSIG(s->wait_status));
	else
		printf("null\n");
	printf("  descendants_remaining: %s\n",
	       s->descendants_remaining ? "true" : "false");
	printf("  descendants_followed: %s\n",
	       s->descendants_followed ? "true" : "false");
	printf("  map_update_failures: %llu\n",
	       (unsigned long long)s->map_failures);
	printf("  ring_reservation_failures: %llu\n",
	       (unsigned long long)s->ring_failures);
	printf("  capset_read_failures: %llu\n",
	       (unsigned long long)s->capset_read_failures);
	printf("  userspace_failures: %lu\n", s->userspace_failures);
}

const char *audit_namespace_scope(void)
{
	if (state.foreign_target_ns_observed)
		return "foreign";
	if (!state.baseline_user_ns_inum || state.unknown_target_ns_observed)
		return "unknown";
	return "baseline";
}

/* Renderers must apply the same decision before offering deployment advice. */
const char *audit_recommendation_reason(void)
{
	const char *incomplete = audit_collection_reason();

	if (incomplete)
		return incomplete;
	if (state.foreign_target_ns_observed)
		return "foreign_user_namespace";
	if (!state.baseline_user_ns_inum || state.unknown_target_ns_observed)
		return "unknown_user_namespace";
	return NULL;
}
