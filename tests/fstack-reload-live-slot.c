/* Test-only role/mapping/fatal interception around the actual production TU.
 * No hook is compiled into or installed with ker::reload. */
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_memzone.h>
#include <rte_debug.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "check.h"
static enum rte_proc_type_t p1_process_type;
static pid_t p1_parent;
static struct rte_memzone mapping;
static jmp_buf fatal;
static unsigned fatal_count;
static int expecting_fatal;
static char test_runtime_dir[] = "/tmp/ker-reload-live-slot-XXXXXX";
static enum rte_proc_type_t test_role(void) { return p1_process_type; }
static const struct rte_memzone *test_lookup(const char *name)
{
    CHECK(!strcmp(name, "ff_reload_gendir")); return &mapping;
}
static void test_exit(int code, const char *format, ...) __attribute__((noreturn));
static void test_exit(int code, const char *format, ...)
{
    CHECK(expecting_fatal && code == EXIT_FAILURE);
    CHECK(strstr(format, "cannot register this") && strstr(format, "cross-master epoch isolation"));
    ++fatal_count; longjmp(fatal, 1);
}
#define rte_eal_process_type test_role
#define rte_eal_get_runtime_dir() test_runtime_dir
#define rte_lcore_count() 1u
#define rte_memzone_lookup test_lookup
#define rte_exit test_exit
#include "../src/compat/reload.c"
#undef rte_exit
#undef rte_memzone_lookup
#undef rte_eal_process_type
#undef rte_lcore_count
#undef rte_eal_get_runtime_dir
static struct ff_reload_gendir *p1_dir;
#define __real_getppid getppid
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_memory_equal(a, b, size) CHECK(!memcmp((a), (b), (size)))
#define expect_assert_failure(call) do { \
    expecting_fatal = 1; \
    if (!setjmp(fatal)) { call; CHECK(0); } \
    expecting_fatal = 0; \
} while (0)
#include "fstack-reload-live-slot-source.inc"
static int record_poll(void *arg)
{
    ++*(unsigned *)arg;
    return 0;
}

/* A second process competes for the orphan's derived slot. Both processes
 * run the public adapter over a shared directory with real file locks. */
static void polling_keeps_slot_live(void)
{
    struct ff_reload_state state;
    struct ff_reload_gendir *directory = mmap(NULL, sizeof(*directory),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(directory != MAP_FAILED && mkdtemp(test_runtime_dir));
    directory->magic = FF_RELOAD_GENDIR_MAGIC;
    directory->version = FF_RELOAD_GENDIR_VERSION;
    directory->len = sizeof(*directory);
    directory->slot_max = FF_RELOAD_EPOCH_SLOT_MAX;
    directory->gen_max = FF_RELOAD_GEN_MAX;
    directory->next_epoch = 3; /* Epoch 4 maps back to slot 1. */
    directory->rx_owner_word = pack_coord(1, 0);
    mapping.addr = directory;
    mapping.len = sizeof(*directory);
    p1_process_type = RTE_PROC_SECONDARY;
    CHECK(!ker_reload_state_init(&state, sizeof(state), 0));
    CHECK(!ker_reload_bind_state(&state, sizeof(state), 1, 0));
    CHECK(!ker_reload_worker_select(0, 0));

    int status;
    pid_t dead = fork();
    CHECK(dead >= 0);
    if (!dead) _exit(0);
    CHECK(waitpid(dead, &status, 0) == dead && WIFEXITED(status));
    uint32_t initial_stamp = (uint32_t)gendir_now_ms();
    directory->slot[1] = (struct ff_reload_epoch_slot){
        .epoch = 1, .master_pid = (uint32_t)dead, .state = FF_RELOAD_SLOT_LIVE,
        .pad = initial_stamp,
    };
    pid_t contender = fork();
    CHECK(contender >= 0);
    if (!contender) {
        ff_reload_reclaim_timeout_set(FF_RELOAD_SLOT_STALE_MS + 1000);
        expect_assert_failure(ker_reload_directory_attach());
        _exit(0);
    }

    CHECK(!ff_reload_gendir_install(directory, sizeof(*directory)));
    g_dir = directory;
    g_dir_slot = 1;
    g_dir_epoch = 1;
    ff_reload_dir_sync_enable(1);
    while (__atomic_load_n(&directory->next_epoch, __ATOMIC_SEQ_CST) == 3) {
        CHECK(waitpid(contender, &status, WNOHANG) == 0);
        usleep(1000);
    }
    unsigned callbacks = 0;
    for (;;) {
        CHECK(!ker_reload_poll(record_poll, &callbacks));
        pid_t done = waitpid(contender, &status, WNOHANG);
        CHECK(done >= 0);
        if (done == contender) break;
        usleep(50000);
    }
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(callbacks && directory->slot[1].pad != initial_stamp);
    CHECK(directory->reclaim_refused == 1 && directory->slot[1].epoch == 1 &&
        directory->slot[1].master_pid == (uint32_t)dead);
    CHECK(!ker_reload_directory_user_release());
    ker_reload_unbind_state();
    /* After polling stops, the next colliding epoch can take that very slot
     * when the final stamp naturally ages out. */
    directory->next_epoch = 6;
    CHECK(!ker_reload_bind_state(&state, sizeof(state), 7, 0));
    CHECK(!ker_reload_worker_select(0, 0));
    CHECK(!ker_reload_directory_attach());
    CHECK(g_dir_slot == 1 && g_dir_epoch == 7 && directory->reclaim_refused == 1);
    CHECK(directory->slot[1].master_pid == (uint32_t)getppid());
    CHECK(ff_reload_gendir_reset_pending_peek());
    CHECK(!ker_reload_directory_user_release());
    ker_reload_unbind_state();
    CHECK(!munmap(directory, sizeof(*directory)));
    int root = open(test_runtime_dir, O_DIRECTORY | O_RDONLY);
    CHECK(root >= 0);
    CHECK(!unlinkat(root, DIRECTORY_REGISTRATION_LOCK, 0));
    CHECK(!unlinkat(root, DIRECTORY_ADMISSION_LOCK, 0));
    CHECK(!close(root) && !rmdir(test_runtime_dir));
}

int main(void)
{
    struct ff_reload_gendir directory = {0};
    p1_dir = &directory; mapping.addr = p1_dir; mapping.len = sizeof(*p1_dir);
    p1_dir->magic = FF_RELOAD_GENDIR_MAGIC; p1_dir->version = FF_RELOAD_GENDIR_VERSION;
    p1_dir->len = sizeof(*p1_dir); p1_dir->slot_max = FF_RELOAD_EPOCH_SLOT_MAX; p1_dir->gen_max = FF_RELOAD_GEN_MAX;
    p1_dir->active_word = p1_dir->rx_owner_word = p1_dir->kni_owner_word = (uint64_t)1 << 32;
    struct ff_reload_state state = {0}; ff_reload_attach_state(&state);
    ff_global_cfg.dpdk.graceful_reload = 1;
    test_p1_directory_live_slot(NULL);
    CHECK(fatal_count == 2 && !g_dir && !g_reload_gendir && !g_reload_dir_publish);
    polling_keeps_slot_live();
    puts("PASS: complete original P1 live-slot assertions, two fatal attempts, free alternate untouched");
    return 0;
}
