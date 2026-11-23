#ifndef KER_FF_INGRESS_FREEZE_STATE_H
#define KER_FF_INGRESS_FREEZE_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KER_FF_INGRESS_STATE_MAX_IDS 64U

struct ker_ff_ingress_freeze_state {
	uint64_t lease;
	uint64_t deadline_ns;
	uint64_t attempt_count;
	uint64_t expired_count;
	uint64_t inventory_error_count;
	uint32_t packet_ids[KER_FF_INGRESS_STATE_MAX_IDS];
	size_t packet_count;
	bool armed;
	bool drained;
	bool quarantined;
};

int ker_ff_ingress_state_init(struct ker_ff_ingress_freeze_state *state,
			      uint64_t lease, uint64_t deadline_ns);
int ker_ff_ingress_state_record(struct ker_ff_ingress_freeze_state *state,
				uint32_t packet_id);
int ker_ff_ingress_state_disarm(struct ker_ff_ingress_freeze_state *state,
				uint64_t attempts, uint64_t expired,
				uint64_t inventory_errors);
int ker_ff_ingress_state_prove_drained(struct ker_ff_ingress_freeze_state *state);
int ker_ff_ingress_state_authorize_accept(
	const struct ker_ff_ingress_freeze_state *state, uint64_t lease,
	uint64_t deadline_ns, uint32_t packet_id, uint64_t now_ns);
int ker_ff_ingress_state_finish_accept(struct ker_ff_ingress_freeze_state *state,
				       uint32_t packet_id, bool sent,
				       int ack_status);
void ker_ff_ingress_state_quarantine(struct ker_ff_ingress_freeze_state *state);
bool ker_ff_ingress_state_can_close(
	const struct ker_ff_ingress_freeze_state *state);

#endif
