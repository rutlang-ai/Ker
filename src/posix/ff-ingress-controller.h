#ifndef KER_POSIX_FF_INGRESS_CONTROLLER_H
#define KER_POSIX_FF_INGRESS_CONTROLLER_H

#include "ff-ingress-freeze-queue.h"

/* Private ker-posix/server bridge. Inputs are broker-owned APP fd numbers;
 * this DSO pins their ker_fd entries and keeps raw LKL descriptors private. */
struct ker_posix_ff_ingress_controller;
int ker_posix_ff_ingress_controller_start(int old_listener_app_fd,
    int candidate_listener_app_fd, int candidate_task_listener_app_fd,
    uint32_t old_mark, uint64_t old_cookie, uint32_t candidate_mark,
    uint64_t candidate_cookie,
    struct ker_posix_ff_ingress_controller **controller);
/* 0 means setup is still running, 1 means q88 is armed and identities remain
 * valid, and a negative result means setup failed (possibly requiring
 * terminal quarantine). */
int ker_posix_ff_ingress_controller_start_poll(
    struct ker_posix_ff_ingress_controller *controller,
    uint64_t *lease, uint64_t *deadline_ns, int *arm_succeeded);
int ker_posix_ff_ingress_controller_check(
    struct ker_posix_ff_ingress_controller *controller);
int ker_posix_ff_ingress_controller_receive(
    struct ker_posix_ff_ingress_controller *controller,
    struct ker_ff_ingress_packet *packet);
int ker_posix_ff_ingress_controller_disarm(
    struct ker_posix_ff_ingress_controller *controller);
int ker_posix_ff_ingress_controller_counts(
    const struct ker_posix_ff_ingress_controller *controller,
    uint64_t *attempts, uint64_t *expired, uint64_t *inventory_errors);
int ker_posix_ff_ingress_controller_drain(
    struct ker_posix_ff_ingress_controller *controller,
    struct ker_ff_ingress_packet *packet);
int ker_posix_ff_ingress_controller_accept_begin(
    struct ker_posix_ff_ingress_controller *controller,
    uint64_t lease, uint64_t deadline_ns, uint32_t packet_id,
    int *sent_to_kernel);
int ker_posix_ff_ingress_controller_accept_poll(
    struct ker_posix_ff_ingress_controller *controller);
int ker_posix_ff_ingress_controller_quarantine(
    struct ker_posix_ff_ingress_controller **controller);
int ker_posix_ff_ingress_controller_close(
    struct ker_posix_ff_ingress_controller *controller);
/* Called by ker_posix_run before admission/runtime shutdown. On failure the
 * kernel remains live and a later same-run cleanup continuation may retry. */
int ker_posix_ff_ingress_controller_prepare_runtime_shutdown(void);
#ifdef KER_C28_CUTOVER_TESTING
int ker_posix_ff_ingress_controller_test_registry_race(void);
#endif

#endif
