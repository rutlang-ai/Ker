/* Private fixture access, never installed: compile the actual production TU
 * with exactly its namespace definitions. Raw original directory fields are
 * preconditions for assertion-level upstream contracts, not public setters.
 * Real EAL multiprocess/PMD qualification is still required before counting
 * any of these source cases complete. */
#include "../src/compat/reload.c"
#include "check.h"
#include "eal.h"
#include <sys/wait.h>

static void directory_init(struct ff_reload_gendir *directory)
{
    memset(directory, 0, sizeof(*directory));
    directory->magic = FF_RELOAD_GENDIR_MAGIC;
    directory->version = FF_RELOAD_GENDIR_VERSION;
    directory->len = sizeof(*directory);
    directory->slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    directory->gen_max = FF_RELOAD_GEN_MAX;
    directory->active_word = directory->rx_owner_word = directory->kni_owner_word =
        (uint64_t)FF_RELOAD_EPOCH_NONE << 32;
    CHECK(!ff_reload_gendir_install(directory, sizeof(*directory)));
    g_dir = directory;
    g_dir_slot = -1;
}

static uint32_t dead_pid(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) _exit(0);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(kill(pid, 0) == -1 && errno == ESRCH);
    return (uint32_t)pid;
}

static void hardware_users(void)
{
    struct ff_reload_gendir directory;
    directory_init(&directory);
    uint32_t gone = dead_pid();
    ff_reload_set_epoch(1); ff_reload_set_gen(0);
    unsigned active; int clear;
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 0 && clear);
    directory.user[0] = (struct ff_reload_hw_user){1, 0, (uint32_t)getppid(), FF_RELOAD_USER_ACTIVE};
    directory.user[1] = (struct ff_reload_hw_user){1, 0, gone, FF_RELOAD_USER_ACTIVE};
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 1 && !clear);
    CHECK(!ff_reload_gendir_epoch_users_clear(1));
    CHECK(!ff_reload_gendir_user_add(1, 0) && !ff_reload_gendir_user_add(1, 0));
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 2 && !clear);
    ff_reload_gendir_user_stop(1, 0);
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 1 && !clear);
    struct ff_reload_hw_user *self = user_self(directory.user, FF_RELOAD_GENDIR_USER_MAX, 1, 0, (uint32_t)getpid());
    CHECK(self && self->state == FF_RELOAD_USER_STOPPED && self->pid == (uint32_t)getpid());
    CHECK(ker_reload_directory_detach() == -EBUSY);
    directory.user[0].state = FF_RELOAD_USER_STOPPED;
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 0 && clear);
    directory.user[2] = (struct ff_reload_hw_user){2, 1, (uint32_t)getppid(), FF_RELOAD_USER_ACTIVE};
    CHECK(!ker_reload_directory_users(2, 1, &active, &clear) && active == 1 && !clear);
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 0 && clear);
    ff_reload_gendir_user_release(1, 0);
    CHECK(!self->pid && self->state == FF_RELOAD_USER_FREE);
    CHECK(!ker_reload_directory_users(1, 0, &active, &clear) && active == 0 && clear);
    CHECK(!ker_reload_directory_detach());
    CHECK(!g_dir && !g_reload_gendir);
}

static void primary_probe_fallback(void)
{
    struct ff_reload_gendir directory;
    directory_init(&directory);
    uint32_t pid = (uint32_t)getpid();
    directory.slot[0] = (struct ff_reload_epoch_slot){.epoch=0, .master_pid=pid, .state=FF_RELOAD_SLOT_LIVE, .flags=FF_RELOAD_SLOT_PRIMARY};
    directory.slot[1] = (struct ff_reload_epoch_slot){.epoch=1, .gen=0, .master_pid=pid, .state=FF_RELOAD_SLOT_LIVE};
    directory.slot[2] = (struct ff_reload_epoch_slot){.epoch=2, .gen=1, .master_pid=pid, .state=FF_RELOAD_SLOT_LIVE};
    ff_reload_set_epoch(0); ff_reload_set_gen(0);
    ff_global_cfg.dpdk.graceful_reload = 1;
    ker_ipc_message message = {0};
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    CHECK(message.reload.epoch == 2 && message.reload.active_gen == 1);
    directory.slot[2].state = FF_RELOAD_SLOT_DEAD;
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    CHECK(message.reload.epoch == 1 && message.reload.active_gen == 0);
    directory.slot[1].state = FF_RELOAD_SLOT_DEAD;
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    CHECK(message.reload.epoch == 0);
    directory.slot[1].state = directory.slot[2].state = FF_RELOAD_SLOT_LIVE;
    ff_reload_gendir_active_set(1, 0);
    ker_reload_message_fill(&message, FF_RELOAD_CMD_QUERY, 0, 0, 0);
    CHECK(message.reload.epoch == 1 && message.reload.active_gen == 0);
    CHECK(!ker_reload_directory_detach());
    ff_global_cfg.dpdk.graceful_reload = 0;
}

/* Unchanged pinned source tests; CHECK replaces only cmocka's assertion host. */
#define assert_int_equal(left, right) CHECK((left) == (right))
#define assert_true(value) CHECK(value)
#include "fstack-reload-directory-source.inc"
#define assert_int_not_equal(left, right) CHECK((left) != (right))
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_string_equal(left, right) CHECK(!strcmp((left), (right)))
#include "fstack-reload-m5-source.inc"

int main(int argc, char **argv)
{
    if (argc == 2) {
        if (!strcmp(argv[1], "hw-users")) test_p2_hw_user_proof(NULL);
        else if (!strcmp(argv[1], "reclaim")) test_p2_reclaim_needs_user_proof(NULL);
        else if (!strcmp(argv[1], "release")) test_p2_release_epoch_needs_proof(NULL);
        else if (!strcmp(argv[1], "orphans")) test_p2_orphan_workers_keep_epoch_live(NULL);
        else if (!strcmp(argv[1], "ring-census")) test_rx15_ring_user_census_and_purge_lock(NULL);
        else if (!strcmp(argv[1], "m5-arbitration")) test_ut_nr_m5_gendir_arbitration(NULL);
        else if (!strcmp(argv[1], "m5-probe")) test_ut_nr_m5_probe_epoch_fallback(NULL);
        else if (!strcmp(argv[1], "m5-names")) test_ut_nr_m5_cross_master_name_isolation(NULL);
        else if (!strcmp(argv[1], "m5-handover")) test_ut_nr_m5_cross_master_handover_sequence(NULL);
        else CHECK(0);
    } else {
        CHECK(argc == 1);
        hardware_users(); primary_probe_fallback();
        test_p2_hw_user_proof(NULL); test_p2_reclaim_needs_user_proof(NULL);
        test_p2_release_epoch_needs_proof(NULL); test_p2_orphan_workers_keep_epoch_live(NULL);
        test_rx15_ring_user_census_and_purge_lock(NULL);
        test_ut_nr_m5_gendir_arbitration(NULL); test_ut_nr_m5_probe_epoch_fallback(NULL);
        test_ut_nr_m5_cross_master_name_isolation(NULL); test_ut_nr_m5_cross_master_handover_sequence(NULL);
    }
    puts("PASS: directory source assertions; multiprocess qualification required");
    return 0;
}
