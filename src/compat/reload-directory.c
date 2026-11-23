/* Included by reload.c so lifecycle checks can cover both original mappings.
 * Keep upstream globals private and upstream source bytes unchanged. */
static int directory_log_type = -1;
static int directory_retiring;

static uint64_t directory_monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

/* Serialize directory lifecycle decisions across EAL processes. This stable
 * runtime-directory inode is separate from DPDK's memzone/config lock files. */
static int directory_registration_lock(int operation)
{
    const char *runtime_dir = rte_eal_get_runtime_dir();
    if (!runtime_dir || !*runtime_dir) return -ENODEV;
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/ker-reload-gendir-register.lock", runtime_dir);
    if (length < 0 || (size_t)length >= sizeof(path)) return -ENAMETOOLONG;
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0660);
    if (fd < 0) return -errno;
    struct stat file_status;
    if (fstat(fd, &file_status) != 0) {
        int error = errno;
        close(fd);
        return -error;
    }
    if (!S_ISREG(file_status.st_mode)) {
        close(fd);
        return -EINVAL;
    }

    uint64_t start = directory_monotonic_ms();
    if (!start) { close(fd); return -EIO; }
    for (;;) {
        if (flock(fd, operation | LOCK_NB) == 0) return fd;
        int error = errno;
        if (error != EINTR && error != EWOULDBLOCK && error != EAGAIN) {
            close(fd);
            return -error;
        }
        uint64_t now = directory_monotonic_ms();
        if (!now || now - start >= 10000u) {
            close(fd);
            return now ? -ETIMEDOUT : -EIO;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 2000000};
        (void)nanosleep(&delay, NULL);
    }
}

static void directory_registration_unlock(int fd)
{
    (void)flock(fd, LOCK_UN);
    (void)close(fd);
}

int ff_log(uint32_t level, uint32_t type, const char *format, ...)
{
    (void)type; /* The imported backend uses only FF_LOGTYPE_FSTACK_LIB. */
    va_list args;
    va_start(args, format);
    int result = rte_vlog(level, directory_log_type, format, args);
    va_end(args);
    return result;
}

_Static_assert(KER_RELOAD_DIRECTORY_SLOTS == FF_RELOAD_EPOCH_SLOT_MAX, "directory slot ABI");
_Static_assert(KER_RELOAD_DIRECTORY_GENERATIONS == FF_RELOAD_GEN_MAX, "directory generation ABI");

/* Foreign ownership can only move through the original proof-bearing reclaim
 * or release operations. In particular, a delayed orphan may still hold an
 * ACTIVE hardware lease after its master's timestamp becomes stale. Disable
 * implicit publication for foreign coordinates while retaining the original
 * local/foreign ownership gate. There is no ownership or protocol substitute. */
static int directory_no_hw_mode(void)
{
    if (!g_dir) return ff_no_hw_mode();
    if (rte_eal_process_type() != RTE_PROC_SECONDARY) return 1;
    if (directory_retiring) return 1;
    uint32_t epoch = FF_RELOAD_EPOCH_NONE, stopped = 0;
    ff_reload_gendir_rx_owner(&epoch, NULL, &stopped);
    if (epoch == FF_RELOAD_EPOCH_NONE) {
        /* Use the original CAS operation for concurrent first claimants,
         * before the original block mirror can publish by ordinary store. */
        if (ff_reload_gendir_rx_reclaim(ff_reload_epoch(), (uint32_t)ff_reload_gen()) != FF_RELOAD_HANDOVER_OK)
            return 1;
        ff_reload_gendir_rx_owner(&epoch, NULL, &stopped);
    }
    int saved = g_reload_dir_publish;
    /* A target's private block may still say unparked while the directory
     * carries the previous owner's park order. Only explicit claim may clear
     * that order; mirroring the target's stale block must not clear it. */
    if (epoch != ff_reload_epoch() || (stopped && !ff_reload_rx_stopped())) {
        ff_reload_dir_sync_enable(0);
        /* The original mirror also refreshes the worker's liveness stamp and
         * peer observation. Keep those runtime observations progressing while
         * foreign ownership waits for an explicit proof-bearing transfer. */
        uint32_t peer; int generation;
        ff_reload_peer_coord(&peer, &generation);
        __atomic_store_n(&g_reload_state->peer_epoch, peer, __ATOMIC_SEQ_CST);
        __atomic_store_n(&g_reload_state->peer_gen, (uint32_t)generation, __ATOMIC_SEQ_CST);
        uint32_t now = (uint32_t)gendir_now_ms();
        uint32_t stamp = __atomic_load_n(&g_dir->slot[g_dir_slot].pad, __ATOMIC_SEQ_CST);
        if ((uint32_t)(now - stamp) >= FF_RELOAD_SLOT_STALE_MS / 2)
            __atomic_store_n(&g_dir->slot[g_dir_slot].pad, now, __ATOMIC_SEQ_CST);
    }
    int result = ff_no_hw_mode();
    ff_reload_dir_sync_enable(saved);
    return result;
}

static int directory_context(void)
{
    if (polling) return -EBUSY;
    if (!g_dir) return -ENOTCONN;
    return 0;
}

static int directory_worker(void)
{
    int result = directory_context();
    if (result) return result;
    return rte_eal_process_type() == RTE_PROC_SECONDARY ? 0 : -EPERM;
}

static int directory_has_user(const struct ff_reload_hw_user *users,
    unsigned count, uint32_t pid, uint32_t epoch, int match_epoch)
{
    for (unsigned i = 0; i < count; ++i) {
        uint32_t p = __atomic_load_n(&users[i].pid, __ATOMIC_SEQ_CST);
        if (!p || (pid && p != pid)) continue;
        if (match_epoch && __atomic_load_n(&users[i].epoch, __ATOMIC_SEQ_CST) != epoch) continue;
        if (__atomic_load_n(&users[i].state, __ATOMIC_SEQ_CST) != FF_RELOAD_USER_FREE && pid_alive(p)) return 1;
    }
    return 0;
}

static int directory_self_leases(void)
{
    uint32_t pid = (uint32_t)getpid();
    return directory_has_user(g_dir->user, FF_RELOAD_GENDIR_USER_MAX, pid, 0, 0) ||
        directory_has_user(g_dir->ring_user, FF_RELOAD_GENDIR_RING_USER_MAX, pid, 0, 0) ||
        __atomic_load_n(&g_dir->ring_purge_owner, __ATOMIC_SEQ_CST) == pid;
}

int ker_reload_directory_attach(void)
{
    if (polling || polled || g_dir) return -EBUSY;
    if (!borrowed) return -ENOTCONN;
    if (!ff_global_cfg.dpdk.graceful_reload || g_reload_slot < 0) return -EINVAL;
    enum rte_proc_type_t role = rte_eal_process_type();
    /* DPDK's pre-init process type defaults to PRIMARY; role alone does not
     * establish a configured EAL. The caller still owns successful init and
     * must never call this after EAL cleanup. */
    if (!rte_lcore_count() || (role != RTE_PROC_PRIMARY && role != RTE_PROC_SECONDARY)) return -ENODEV;
    int registration_fd = directory_registration_lock(LOCK_EX);
    if (registration_fd < 0) return registration_fd;
    if (directory_log_type < 0) {
        directory_log_type = rte_log_register("ker.reload.directory");
        if (directory_log_type < 0) {
            directory_registration_unlock(registration_fd);
            return -ENOMEM;
        }
    }
    ff_reload_gendir_attach(); /* Required attach retains original fatal errors. */
    directory_retiring = 0;
    if (role == RTE_PROC_SECONDARY) {
        /* Track even a worker that has not polled yet. Otherwise another
         * departing orphan could retire the epoch beneath this borrower. */
        if (ff_reload_gendir_user_add(ff_reload_epoch(), ff_reload_gen())) {
            (void)ker_reload_directory_detach();
            directory_registration_unlock(registration_fd);
            return -ENOSPC;
        }
        ff_reload_gendir_user_stop(ff_reload_epoch(), ff_reload_gen());
    }
    directory_registration_unlock(registration_fd);
    return 0;
}

int ker_reload_directory_detach(void)
{
    int result = directory_context();
    if (result) return result;
    if (directory_self_leases()) return -EBUSY;
    /* Upstream retire keys on the master PID. A departing orphan must not
     * mark an epoch DEAD while another registered orphan still borrows it. */
    if (directory_has_user(g_dir->user, FF_RELOAD_GENDIR_USER_MAX, 0, ff_reload_epoch(), 1) ||
        directory_has_user(g_dir->ring_user, FF_RELOAD_GENDIR_RING_USER_MAX, 0, ff_reload_epoch(), 1))
        g_dir_slot = -1;
    ff_reload_gendir_detach();
    (void)ff_reload_gendir_reset_pending();
    ff_reload_dir_sync_enable(0);
    directory_retiring = 0;
    return 0;
}

int ker_reload_directory_destroy(void)
{
    int result = directory_context();
    if (result) return result;
    if (rte_eal_process_type() != RTE_PROC_PRIMARY) return -EPERM;
    if (directory_self_leases()) return -EBUSY;
    for (unsigned i = 1; i < FF_RELOAD_EPOCH_SLOT_MAX; ++i) {
        uint32_t owner = __atomic_load_n(&g_dir->slot[i].master_pid, __ATOMIC_SEQ_CST);
        if (owner && (pid_alive(owner) || ff_reload_gendir_epoch_live(__atomic_load_n(&g_dir->slot[i].epoch, __ATOMIC_SEQ_CST)))) return -EBUSY;
    }
    if (directory_has_user(g_dir->user, FF_RELOAD_GENDIR_USER_MAX, 0, 0, 0) ||
        directory_has_user(g_dir->ring_user, FF_RELOAD_GENDIR_RING_USER_MAX, 0, 0, 0) ||
        pid_alive(__atomic_load_n(&g_dir->ring_purge_owner, __ATOMIC_SEQ_CST))) return -EBUSY;
    const struct rte_memzone *zone = rte_memzone_lookup(FF_RELOAD_GENDIR_NAME);
    if (!zone || zone->addr != g_dir) return -EINVAL;
    result = ker_reload_directory_detach();
    if (result) return result;
    return rte_memzone_free(zone) ? -(rte_errno ? rte_errno : EIO) : 0;
}

int ker_reload_directory_view(struct ker_reload_directory_view *view)
{
    if (!view) return -EINVAL;
    if (!g_dir) return -ENOTCONN;
    *view = (struct ker_reload_directory_view){
        .self = {ff_reload_epoch(), (uint32_t)ff_reload_gen()},
        .slot = (uint32_t)g_dir_slot,
        .reclaim_refused = ff_reload_gendir_reclaim_refused(),
        .reclaim_forced = ff_reload_gendir_reclaim_forced(),
        .recycled_slot = ff_reload_gendir_reset_pending_peek()};
    ff_reload_gendir_active(&view->active.epoch, &view->active.generation);
    ff_reload_gendir_rx_owner(&view->rx_owner.epoch, &view->rx_owner.generation, &view->stopped);
    ff_reload_gendir_kni_owner(&view->observation_owner.epoch, &view->observation_owner.generation);
    return 0;
}

int ker_reload_directory_epoch_live(uint32_t epoch)
{
    if (!g_dir) return -ENOTCONN;
    return ff_reload_gendir_epoch_live(epoch);
}

int ker_reload_directory_peer(struct ker_reload_peer *peer)
{
    if (!peer) return -EINVAL;
    if (!g_dir) return -ENOTCONN;
    int generation;
    ff_reload_peer_coord(&peer->selected.epoch, &generation);
    peer->selected.generation = (uint32_t)generation;
    ff_reload_peer_block(&peer->published.epoch, &peer->published.generation);
    peer->foreign = ff_reload_peer_draining();
    peer->published_foreign = ff_reload_peer_mirror_draining();
    peer->observation_owner_matches = ff_reload_kni_owner_match();
    return 0;
}

int ker_reload_directory_users(uint32_t epoch, int generation, unsigned *active, int *clear)
{
    if (!g_dir) return -ENOTCONN;
    if (epoch == FF_RELOAD_EPOCH_NONE || generation < 0 || generation >= FF_RELOAD_GEN_MAX) return -EINVAL;
    if (active) *active = (unsigned)ff_reload_gendir_users_active(epoch, generation);
    if (clear) *clear = ff_reload_gendir_users_clear(epoch, generation);
    return 0;
}

int ker_reload_directory_user_stop(void)
{
    int result = directory_worker();
    if (result) return result;
    ff_reload_gendir_user_stop(ff_reload_epoch(), ff_reload_gen());
    return 0;
}

int ker_reload_directory_user_release(void)
{
    int result = directory_worker();
    if (result) return result;
    ff_reload_gendir_user_release(ff_reload_epoch(), ff_reload_gen());
    directory_retiring = 1;
    return 0;
}

int ker_reload_directory_release(uint32_t epoch, int generation)
{
    int result = directory_worker();
    if (result) return result;
    if (directory_retiring) return -ESHUTDOWN;
    if (epoch == 0 || epoch == FF_RELOAD_EPOCH_NONE || generation < 0 || generation >= FF_RELOAD_GEN_MAX) return FF_RELOAD_HANDOVER_INVAL;
    uint32_t owner = FF_RELOAD_EPOCH_NONE, gen = 0;
    ff_reload_gendir_rx_owner(&owner, &gen, NULL);
    if (owner == epoch && gen == (uint32_t)generation) return FF_RELOAD_HANDOVER_OK;
    if (owner != ff_reload_epoch() || gen != (uint32_t)ff_reload_gen()) return FF_RELOAD_HANDOVER_BUSY;
    return ff_reload_rx_release_epoch(epoch, generation);
}

int ker_reload_directory_claim(uint32_t from_epoch, int from_generation, unsigned timeout_ms)
{
    int result = directory_worker();
    if (result) return result;
    if (directory_retiring) return -ESHUTDOWN;
    if (from_epoch == FF_RELOAD_EPOCH_NONE || from_generation < 0 || from_generation >= FF_RELOAD_GEN_MAX) return FF_RELOAD_HANDOVER_INVAL;
    result = ff_reload_gendir_rx_claim(from_epoch, (uint32_t)from_generation,
        ff_reload_epoch(), (uint32_t)ff_reload_gen(), timeout_ms);
    if (result == FF_RELOAD_HANDOVER_OK) {
        __atomic_store_n(&g_reload_state->reserved[4], 0u, __ATOMIC_SEQ_CST);
        ff_reload_rx_owner_gen_set(ff_reload_gen());
        ff_reload_rx_stopped_set(0);
    }
    return result;
}

int ker_reload_directory_reclaim(void)
{
    int result = directory_worker();
    if (result) return result;
    if (directory_retiring) return -ESHUTDOWN;
#ifndef KER_RELOAD_TESTING_NO_RECLAIM_GATE
    int registration_fd = directory_registration_lock(LOCK_EX);
    if (registration_fd < 0) return registration_fd;
#endif
    result = ff_reload_gendir_rx_reclaim(ff_reload_epoch(), (uint32_t)ff_reload_gen());
    if (result == FF_RELOAD_HANDOVER_OK) {
        __atomic_store_n(&g_reload_state->reserved[4], 0u, __ATOMIC_SEQ_CST);
        ff_reload_rx_owner_gen_set(ff_reload_gen());
        ff_reload_rx_stopped_set(0);
    }
#ifndef KER_RELOAD_TESTING_NO_RECLAIM_GATE
    directory_registration_unlock(registration_fd);
#endif
    return result;
}

int ker_reload_directory_ring_attach(unsigned wait_ms)
{
    int result = directory_worker();
    if (result) return result;
    if (directory_retiring) return -ESHUTDOWN;
    return ff_reload_gendir_ring_attach(ff_reload_epoch(), ff_reload_gen(), wait_ms);
}

int ker_reload_directory_ring_detach(void)
{
    int result = directory_worker();
    if (result) return result;
    ff_reload_gendir_ring_detach(ff_reload_epoch(), ff_reload_gen());
    return 0;
}

int ker_reload_directory_ring_census(
    uint32_t live[KER_RELOAD_DIRECTORY_SLOTS][KER_RELOAD_DIRECTORY_GENERATIONS],
    uint32_t dead[KER_RELOAD_DIRECTORY_SLOTS][KER_RELOAD_DIRECTORY_GENERATIONS], int clear_idle)
{
    int result = directory_context();
    if (result) return result;
    if (!live || !dead || (clear_idle != 0 && clear_idle != 1)) return -EINVAL;
    if (clear_idle && __atomic_load_n(&g_dir->ring_purge_owner, __ATOMIC_SEQ_CST) != (uint32_t)getpid()) return -EPERM;
    return ff_reload_gendir_ring_census(live, dead, clear_idle);
}

int ker_reload_directory_purge_lock(unsigned wait_ms)
{
    int result = directory_context();
    if (result) return result;
    return ff_reload_gendir_ring_purge_lock(wait_ms);
}

int ker_reload_directory_purge_unlock(void)
{
    int result = directory_context();
    if (result) return result;
    if (__atomic_load_n(&g_dir->ring_purge_owner, __ATOMIC_SEQ_CST) != (uint32_t)getpid()) return -EPERM;
    ff_reload_gendir_ring_purge_unlock();
    return 0;
}
