/* Real primary EAL consumer of the exported production component. */
#define _GNU_SOURCE
#include <ker/reload-directory.h>
#include <ker/reload.h>
#include "ff_reload.h" /* Exact layout for caller-owned state storage. */
#include "eal.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <rte_memzone.h>

static int must_not_poll(void *argument)
{
    (void)argument;
    CHECK(0);
    return 0;
}

static void verify_primary_query_pid_cache(void)
{
    const struct rte_memzone *mz = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
    CHECK(mz);
    struct ff_reload_gendir *directory = mz->addr;
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        for (;;) pause();
    }
    directory->slot[1] = (struct ff_reload_epoch_slot){
        .epoch = 42, .gen = 0, .master_pid = (uint32_t)child,
        .state = FF_RELOAD_SLOT_LIVE,
    };

    ker_ipc_message query = {0};
    ker_reload_message_fill(&query, FF_RELOAD_CMD_QUERY, 0, 0, 7);
    CHECK(query.reload.epoch == 42 && query.reload.active_gen == 0);
    CHECK(!kill(child, SIGKILL));
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status));

    /* The imported peer locator may retain a positive PID result briefly;
     * allow scheduler delays and require bounded convergence to the survivor. */
    uint64_t deadline = rte_get_timer_cycles() + rte_get_timer_hz();
    for (;;) {
        memset(&query, 0, sizeof(query));
        ker_reload_message_fill(&query, FF_RELOAD_CMD_QUERY, 0, 0, 7);
        CHECK(query.reload.epoch == 42 || query.reload.epoch == 0);
        CHECK(query.reload.active_gen == 0);
        if (query.reload.epoch == 0) break;
        CHECK(rte_get_timer_cycles() < deadline);
        usleep(1000);
    }
    memset(&directory->slot[1], 0, sizeof(directory->slot[1]));
}

static void primary_eal(void)
{
    struct ff_reload_state state;
    struct ker_reload_directory_view view;
    uint32_t live[4][2], dead[4][2];
    CHECK(ker_reload_directory_attach() == -ENOTCONN);
    CHECK(!ker_reload_state_init(&state, sizeof(state), 0));
    CHECK(!ker_reload_bind_state(&state, sizeof(state), 0, 0));
    CHECK(ker_reload_directory_attach() == -EINVAL);
    CHECK(!ker_reload_worker_select(0, 0));
    CHECK(ker_reload_directory_attach() == -ENODEV);
    char runtime_template[] = "/tmp/ker-reload-directory-eal-XXXXXX";
    char *runtime_root = mkdtemp(runtime_template);
    CHECK(runtime_root);
    CHECK(!setenv("RUNTIME_DIRECTORY", runtime_root, 1));
    CHECK(!setenv("XDG_RUNTIME_DIR", runtime_root, 1));
    ker_test_eal_init();
    CHECK(!ker_reload_directory_attach());
    CHECK(!ker_reload_directory_view(&view));
    CHECK(view.self.epoch == 0 && view.self.generation == 0 && view.slot == 0);
    CHECK(view.active.epoch == FF_RELOAD_EPOCH_NONE && view.rx_owner.epoch == FF_RELOAD_EPOCH_NONE);
    CHECK(ker_reload_directory_epoch_live(0) == 1);
    verify_primary_query_pid_cache();
    CHECK(ker_reload_directory_attach() == -EBUSY);
    CHECK(ker_reload_worker_select(1, 0) == -EBUSY && ker_reload_set_enabled(0) == -EBUSY);
    CHECK(ker_reload_poll(must_not_poll, NULL) == -EPERM && !ker_reload_rx_allowed());
    CHECK(ker_reload_directory_user_stop() == -EPERM && ker_reload_directory_user_release() == -EPERM);
    CHECK(ker_reload_directory_release(2, 1) == -EPERM && ker_reload_directory_reclaim() == -EPERM);
    CHECK(ker_reload_directory_ring_attach(0) == -EPERM);
    CHECK(!ker_reload_directory_ring_census(live, dead, 0));
    CHECK(!memcmp(live, dead, sizeof(live)));
    CHECK(ker_reload_directory_ring_census(live, dead, 1) == -EPERM);
    CHECK(!ker_reload_directory_purge_lock(0));
    CHECK(!ker_reload_directory_purge_lock(0));
    CHECK(ker_reload_directory_detach() == -EBUSY && ker_reload_directory_destroy() == -EBUSY);
    CHECK(!ker_reload_directory_ring_census(live, dead, 1));
    CHECK(!ker_reload_directory_purge_unlock());
    CHECK(ker_reload_directory_purge_unlock() == -EPERM);
    CHECK(!ker_reload_directory_destroy());
    CHECK(!rte_memzone_lookup(FF_RELOAD_GENDIR_NAME));
    CHECK(ker_reload_directory_view(&view) == -ENOTCONN);
    CHECK(!ker_reload_directory_attach());
    CHECK(!ker_reload_directory_destroy());
    ker_reload_unbind_state();
    CHECK(!rte_eal_cleanup());
    char runtime_parent[PATH_MAX], runtime_prefix[PATH_MAX], registration_lock[PATH_MAX];
    int length = snprintf(runtime_parent, sizeof(runtime_parent), "%s/dpdk", runtime_root);
    CHECK(length > 0 && (size_t)length < sizeof(runtime_parent));
    length = snprintf(runtime_prefix, sizeof(runtime_prefix), "%s/ker-test-%ld", runtime_parent, (long)getpid());
    CHECK(length > 0 && (size_t)length < sizeof(runtime_prefix));
    length = snprintf(registration_lock, sizeof(registration_lock), "%s/ker-reload-gendir-register.lock", runtime_prefix);
    CHECK(length > 0 && (size_t)length < sizeof(registration_lock));
    /* The lock inode must remain stable for every EAL participant. This test
     * removes it only after EAL cleanup has ended the namespace lifetime. */
    CHECK(!unlink(registration_lock));
    CHECK(!rmdir(runtime_prefix));
    CHECK(!rmdir(runtime_parent));
    CHECK(!rmdir(runtime_root));
}

int main(void)
{
    primary_eal();
    puts("PASS: exported directory adapter, primary EAL create/destroy/recreate");
    return 0;
}
