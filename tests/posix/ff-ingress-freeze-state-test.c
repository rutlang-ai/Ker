#include "ff-ingress-freeze-state.h"

#include <errno.h>
#include <stdio.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "ingress freeze state:%d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static int test_healthy_cutoff(void)
{
	struct ker_ff_ingress_freeze_state state;
	CHECK(ker_ff_ingress_state_init(&state, 7, 900) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 11) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 12) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 12) == -EEXIST);
	CHECK(state.quarantined);

	CHECK(ker_ff_ingress_state_init(&state, 7, 900) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 11) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 12) == 0);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 6, 900, 11, 100) == -ESTALE);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 900, 11, 100) == -EBUSY);
	CHECK(ker_ff_ingress_state_disarm(&state, 2, 0, 0) == 0);
	CHECK(ker_ff_ingress_state_prove_drained(&state) == 0);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 901, 11, 100) == -ESTALE);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 900, 13, 100) == -ENOENT);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 900, 11, 900) == -ETIMEDOUT);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 900, 11, 899) == 0);
	CHECK(ker_ff_ingress_state_finish_accept(&state, 11, true, 0) == 0);
	CHECK(ker_ff_ingress_state_finish_accept(&state, 11, true, 0) == -ENOENT);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 7, 900, 12, 899) == 0);
	CHECK(ker_ff_ingress_state_finish_accept(&state, 12, true, 0) == 0);
	CHECK(ker_ff_ingress_state_can_close(&state));
	return 0;
}

static int test_mismatch_and_terminal_quarantine(void)
{
	struct ker_ff_ingress_freeze_state state;
	CHECK(ker_ff_ingress_state_init(&state, 19, 5000) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 3) == 0);
	CHECK(ker_ff_ingress_state_disarm(&state, 2, 0, 0) == 0);
	CHECK(ker_ff_ingress_state_prove_drained(&state) == -EUCLEAN);
	CHECK(state.quarantined);
	CHECK(!ker_ff_ingress_state_can_close(&state));
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 19, 5000, 3, 1) == -ECANCELED);

	CHECK(ker_ff_ingress_state_init(&state, 20, 5000) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 4) == 0);
	CHECK(ker_ff_ingress_state_disarm(&state, 1, 1, 0) == 0);
	CHECK(ker_ff_ingress_state_prove_drained(&state) == -EUCLEAN);

	CHECK(ker_ff_ingress_state_init(&state, 21, 5000) == 0);
	CHECK(ker_ff_ingress_state_disarm(&state, 0, 0, 1) == 0);
	CHECK(ker_ff_ingress_state_prove_drained(&state) == -EUCLEAN);
	return 0;
}

static int test_ack_loss_and_disarmed_quarantine(void)
{
	struct ker_ff_ingress_freeze_state state;
	CHECK(ker_ff_ingress_state_init(&state, 31, 9000) == 0);
	CHECK(ker_ff_ingress_state_record(&state, 42) == 0);
	CHECK(ker_ff_ingress_state_disarm(&state, 1, 0, 0) == 0);
	CHECK(ker_ff_ingress_state_prove_drained(&state) == 0);
	CHECK(ker_ff_ingress_state_finish_accept(&state, 42, false, -EAGAIN) == -EAGAIN);
	CHECK(!state.quarantined);
	CHECK(ker_ff_ingress_state_finish_accept(&state, 42, true, -ECONNRESET) == -ECONNRESET);
	CHECK(state.quarantined);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 31, 9000, 42, 1) == -ECANCELED);
	CHECK(!ker_ff_ingress_state_can_close(&state));

	CHECK(ker_ff_ingress_state_init(&state, 32, 9000) == 0);
	CHECK(ker_ff_ingress_state_disarm(&state, 0, 0, 0) == 0);
	ker_ff_ingress_state_quarantine(&state);
	CHECK(ker_ff_ingress_state_authorize_accept(&state, 32, 9000, 1, 1) == -ECANCELED);
	CHECK(!ker_ff_ingress_state_can_close(&state));
	return 0;
}

int main(void)
{
	CHECK(test_healthy_cutoff() == 0);
	CHECK(test_mismatch_and_terminal_quarantine() == 0);
	CHECK(test_ack_loss_and_disarmed_quarantine() == 0);
	return 0;
}
