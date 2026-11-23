#include "ff-ingress-freeze-state.h"

#include <errno.h>
#include <string.h>

int ker_ff_ingress_state_init(struct ker_ff_ingress_freeze_state *state,
			      uint64_t lease, uint64_t deadline_ns)
{
	if (!state || !lease || !deadline_ns) return -EINVAL;
	memset(state, 0, sizeof(*state));
	state->lease = lease;
	state->deadline_ns = deadline_ns;
	state->armed = true;
	return 0;
}

int ker_ff_ingress_state_record(struct ker_ff_ingress_freeze_state *state,
				uint32_t packet_id)
{
	if (!state || !packet_id || state->quarantined || state->drained ||
	    state->packet_count >= KER_FF_INGRESS_STATE_MAX_IDS)
		return -EINVAL;
	for (size_t i = 0; i < state->packet_count; i++) {
		if (state->packet_ids[i] == packet_id) {
			state->quarantined = true;
			return -EEXIST;
		}
	}
	state->packet_ids[state->packet_count++] = packet_id;
	return 0;
}

int ker_ff_ingress_state_disarm(struct ker_ff_ingress_freeze_state *state,
				uint64_t attempts, uint64_t expired,
				uint64_t inventory_errors)
{
	if (!state || !state->armed || state->quarantined) return -EINVAL;
	state->armed = false;
	state->attempt_count = attempts;
	state->expired_count = expired;
	state->inventory_error_count = inventory_errors;
	return 0;
}

int ker_ff_ingress_state_prove_drained(struct ker_ff_ingress_freeze_state *state)
{
	if (!state || state->armed || state->quarantined) return -EINVAL;
	if (state->attempt_count != state->packet_count || state->expired_count ||
	    state->inventory_error_count) {
		state->quarantined = true;
		return -EUCLEAN;
	}
	state->drained = true;
	return 0;
}

int ker_ff_ingress_state_authorize_accept(
	const struct ker_ff_ingress_freeze_state *state, uint64_t lease,
	uint64_t deadline_ns, uint32_t packet_id, uint64_t now_ns)
{
	if (!state || state->quarantined) return -ECANCELED;
	if (lease != state->lease || deadline_ns != state->deadline_ns)
		return -ESTALE;
	if (state->armed || !state->drained) return -EBUSY;
	if (now_ns >= state->deadline_ns) return -ETIMEDOUT;
	for (size_t i = 0; i < state->packet_count; i++)
		if (state->packet_ids[i] == packet_id) return 0;
	return -ENOENT;
}

int ker_ff_ingress_state_finish_accept(struct ker_ff_ingress_freeze_state *state,
				       uint32_t packet_id, bool sent,
				       int ack_status)
{
	if (!state || state->quarantined) return -ECANCELED;
	size_t index = state->packet_count;
	for (size_t i = 0; i < state->packet_count; i++)
		if (state->packet_ids[i] == packet_id) { index = i; break; }
	if (index == state->packet_count) return -ENOENT;
	if (ack_status) {
		if (sent) state->quarantined = true;
		return ack_status;
	}
	if (!sent) return -EINVAL;
	memmove(&state->packet_ids[index], &state->packet_ids[index + 1],
		(state->packet_count - index - 1) * sizeof(state->packet_ids[0]));
	state->packet_count--;
	return 0;
}

void ker_ff_ingress_state_quarantine(struct ker_ff_ingress_freeze_state *state)
{
	if (state) state->quarantined = true;
}

bool ker_ff_ingress_state_can_close(
	const struct ker_ff_ingress_freeze_state *state)
{
	return state && !state->armed && !state->quarantined && state->drained &&
		!state->packet_count;
}
