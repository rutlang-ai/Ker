#ifndef KER_SOCKET_BROKER_PRELOAD_INTERNAL_H
#define KER_SOCKET_BROKER_PRELOAD_INTERNAL_H

#include <ker/socket-broker.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>

void ker_sb_preload_lock(void);
void ker_sb_preload_unlock(void);
int ker_sb_preload_resolve_host_functions(void);
int ker_sb_preload_host_epoll_pwait(int epfd, struct epoll_event *events,
    int maximum, int timeout, const sigset_t *mask);
struct ker_socket_client *ker_sb_preload_client_locked(void);

/* Returns 1 for a registered/recovered network socket capability, 0 for a
 * host descriptor, or -1 when classification failed and the caller must fail
 * closed. On success, *broker_fd is the private close-on-exec capability. */
int ker_sb_preload_network_fd_locked(int app_fd, int *broker_fd);
int ker_sb_preload_register_network_locked(int app_fd);
void ker_sb_preload_remove_network_locked(int app_fd);

/* Composite epoll app descriptors are real host epoll fds. */
int ker_sb_preload_epoll_fd_locked(int app_fd, int *broker_epoll_fd);
int ker_sb_preload_register_epoll_locked(int app_fd, int broker_epoll_fd);
int ker_sb_preload_register_inherited_epoll_locked(int app_fd);
int ker_sb_preload_duplicate_epoll_locked(int old_fd, int minimum, bool cloexec);
void ker_sb_preload_remove_epoll_locked(int app_fd);
bool ker_sb_preload_has_exec_unsafe_epoll_locked(void);
int ker_sb_preload_close_locked(int fd);
int ker_sb_preload_duplicate_network_locked(int fd, int minimum, bool cloexec);
int ker_sb_preload_composite_epoll_locked(int fd, int *broker_fd);
int ker_sb_preload_any_native_locked(int fd);
int ker_sb_preload_is_private_fd_locked(int fd);
int ker_sb_preload_track_private_fd_locked(int fd);
void ker_sb_preload_untrack_private_fd_locked(int fd);
int ker_sb_preload_epoll_create_locked(int flags);
int ker_sb_preload_epoll_duplicate_locked(int fd, int minimum, bool cloexec);
int ker_sb_preload_epoll_next_remote_first_locked(int fd);
int ker_sb_preload_epoll_wait_mixed_locked(int fd, struct epoll_event *events,
    int maximum, int timeout, const sigset_t *mask);

#endif
