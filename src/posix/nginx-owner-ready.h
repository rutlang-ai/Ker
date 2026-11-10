#ifndef KER_NGINX_OWNER_READY_H
#define KER_NGINX_OWNER_READY_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#define KER_NGINX_OWNER_READY_MAGIC UINT32_C(0x4b4e5244)
#define KER_NGINX_OWNER_READY_VERSION 2
struct ker_nginx_owner_ready_record {
    uint32_t magic;
    uint16_t version, length;
    uint32_t role, reserved;
    uint64_t slot_device, slot_inode, worker_start_time;
    uint32_t worker_pid, owner_tid;
    uint64_t endpoint_cookie, reserved3;
};
_Static_assert(sizeof(struct ker_nginx_owner_ready_record) == 64,
    "Nginx owner READY record must be 64 bytes");

/* Host-only, private pinned-caller transport. Init runs in the master; bind
 * runs in its worker after the authenticated slot claim. Send is called only
 * from the worker's FF event loop and records that owner TID. Success is
 * idempotent; transient pre-transfer errors yield EAGAIN. Zero-initialize the sender before init.
 * Successful init takes ownership of this process copy of fd; failures leave
 * it with the caller. Close checks identity before touching fds. */
struct ker_nginx_owner_ready_sender {
    int fd, peer_pidfd;
    pid_t master_pid, bound_pid;
    struct stat endpoint_identity, pidfd_identity;
    uint64_t cookie, deadline_ns;
    struct ker_nginx_owner_ready_record record;
    bool initialized, sent;
};
int ker_nginx_owner_ready_sender_init(struct ker_nginx_owner_ready_sender *sender,
    int fd, pid_t expected_peer);
int ker_nginx_owner_ready_sender_bind(struct ker_nginx_owner_ready_sender *sender,
    int slot_fd, unsigned role);
int ker_nginx_owner_ready_sender_send(struct ker_nginx_owner_ready_sender *sender);
void ker_nginx_owner_ready_sender_close(struct ker_nginx_owner_ready_sender *sender);
#endif
