#include <ker/ipc.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "check.h"
#include "ff_config.h"
#include "ff_reload.h"

#define assert_int_equal(actual, expected) CHECK((actual) == (expected))
#define assert_true(condition) CHECK(condition)
#include "fstack-reload-source/test_ut_nr_22_heartbeat_and_rx_return.inc"
#include "fstack-reload-source/test_ut_nr_26_rx_handover_markers.inc"
#include "fstack-reload-source/test_ut_nr_11_handover_barrier.inc"
#include "fstack-reload-source/test_ut_nr_m5_gendir_arbitration.inc"
#include "fstack-reload-source/test_ut_nr_m5_probe_epoch_fallback.inc"
#include "fstack-reload-source/test_ut_nr_m5_cross_master_handover_sequence.inc"
#include "fstack-reload-source/user-proof-cases.inc"

#define RELOAD_CASE(test) {#test, test}
static const struct {
    const char *name;
    void (*run)(void **state);
} cases[] = {
    RELOAD_CASE(test_ut_nr_22_heartbeat_and_rx_return),
    RELOAD_CASE(test_ut_nr_26_rx_handover_markers),
    RELOAD_CASE(test_ut_nr_11_handover_barrier),
    RELOAD_CASE(test_ut_nr_m5_gendir_arbitration),
    RELOAD_CASE(test_ut_nr_m5_probe_epoch_fallback),
    RELOAD_CASE(test_ut_nr_m5_cross_master_handover_sequence),
    RELOAD_CASE(test_p2_hw_user_proof),
    RELOAD_CASE(test_p2_reclaim_needs_user_proof),
    RELOAD_CASE(test_p2_release_epoch_needs_proof),
    RELOAD_CASE(test_p2_orphan_workers_keep_epoch_live),
    RELOAD_CASE(test_rx15_ring_user_census_and_purge_lock),
};

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (strcmp(argv[1], cases[i].name) == 0) {
            cases[i].run(NULL);
            CHECK(!ff_reload_state_attached());
            return 0;
        }
    }
    fprintf(stderr, "Unknown reload source case: %s\n", argv[1]);
    return EXIT_FAILURE;
}
