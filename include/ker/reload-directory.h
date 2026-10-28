#ifndef KER_RELOAD_DIRECTORY_H
#define KER_RELOAD_DIRECTORY_H
#include <ker/reload.h>

/* Optional original F-Stack cross-master directory, borrowed from the caller's
 * initialized EAL. Serialize with every ker::reload call in this process.
 * Bind state and select the worker before attach. Primary reserves the original
 * memzone; secondaries look it up and register their real getppid() as master.
 * Missing/incompatible/conflicting directories retain upstream's fatal startup
 * refusal. Precondition errors use negative errno. Attachment fixes this
 * process's generation/worker slot until detach. No EAL teardown is owned here.
 * Every secondary starts with a STOPPED registration, including workers that
 * have not polled yet. Distinct masters require distinct actual parents. */
KER_API int ker_reload_directory_attach(void);
/* Quiesce callbacks, release this process's hardware and ring registrations,
 * and unlock purge first; otherwise EBUSY. Drops both original local mappings.
 * Detach does not free the shared memzone. */
KER_API int ker_reload_directory_detach(void);
/* Primary only. Before calling, the application must prove that ALL other EAL
 * participants have exited (including observers with no registration). Visible
 * live foreign masters/users are an additional refusal, not a substitute for
 * that proof. Frees the original directory memzone and detaches on success. */
KER_API int ker_reload_directory_destroy(void);
enum { KER_RELOAD_DIRECTORY_SLOTS = 4, KER_RELOAD_DIRECTORY_GENERATIONS = 2 };
struct ker_reload_coordinate { uint32_t epoch, generation; };
struct ker_reload_directory_view {
    struct ker_reload_coordinate self, active, rx_owner, observation_owner;
    uint32_t slot, stopped, reclaim_refused, reclaim_forced;
    int recycled_slot;
};
/* Coordinate words are atomic pairs; fields across words are observations,
 * not one coherent global snapshot. Query never publishes ownership. */
KER_API int ker_reload_directory_view(struct ker_reload_directory_view *view);
KER_API int ker_reload_directory_epoch_live(uint32_t epoch);
struct ker_reload_peer {
    struct ker_reload_coordinate selected, published;
    int foreign, published_foreign, observation_owner_matches;
};
/* Original peer selection: newest live foreign epoch outside a reload window,
 * own opposite generation during the window or without a live foreign peer.
 * Published is the original block mirror from the last polling pass. Fields
 * are observations, not one global atomic snapshot. The observation-owner
 * match is a coordinate predicate, not a FreeBSD KNI implementation. */
KER_API int ker_reload_directory_peer(struct ker_reload_peer *peer);
KER_API int ker_reload_directory_users(uint32_t epoch, int generation,
    unsigned *active, int *clear);
/* Poll automatically registers ACTIVE before gating, and acknowledges STOPPED
 * on a denied pass. Its lease survives callback return until a denied pass or
 * explicit stop. Stop/release require no callback in flight and the caller's
 * promise to keep manual hardware work quiescent. These are runtime proofs,
 * not process authentication. Release is terminal for this attachment: poll,
 * claim/reclaim/release and new ring attachment then return ESHUTDOWN. Detach
 * before starting a new attachment. Stop alone permits a later poll. */
KER_API int ker_reload_directory_user_stop(void);
KER_API int ker_reload_directory_user_release(void);
/* Original bounded release waits for every old ACTIVE user to stop or exit.
 * No production timeout override is exposed. Claim never steals; reclaim
 * requires a dead/stale owner and actual user proof. Only the calling
 * secondary's coordinate can claim/reclaim. Return original HANDOVER values. */
KER_API int ker_reload_directory_release(uint32_t epoch, int generation);
KER_API int ker_reload_directory_claim(uint32_t from_epoch, int from_generation,
    unsigned timeout_ms);
KER_API int ker_reload_directory_reclaim(void);
/* Register only this process's own ring coordinate before consuming rings.
 * Detach only after all its ring operations have stopped. Original attach and
 * purge wait results are retained (0/-1); missing attachment uses ENOTCONN. */
KER_API int ker_reload_directory_ring_attach(unsigned wait_ms);
KER_API int ker_reload_directory_ring_detach(void);
KER_API int ker_reload_directory_ring_census(
    uint32_t live[KER_RELOAD_DIRECTORY_SLOTS][KER_RELOAD_DIRECTORY_GENERATIONS],
    uint32_t dead[KER_RELOAD_DIRECTORY_SLOTS][KER_RELOAD_DIRECTORY_GENERATIONS],
    int clear_idle);
/* Lock excludes foreign purgers, not live ring consumers. Hold it across
 * census and purge, and never dequeue a slot with live users. */
KER_API int ker_reload_directory_purge_lock(unsigned wait_ms);
KER_API int ker_reload_directory_purge_unlock(void);
#endif
