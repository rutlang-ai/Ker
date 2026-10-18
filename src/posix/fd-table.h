#ifndef KER_POSIX_FD_TABLE_H
#define KER_POSIX_FD_TABLE_H
#include <stdatomic.h>
#include <stdbool.h>
#define KER_FD_LIMIT 65536

enum ker_fd_kind { KER_FD_SOCKET, KER_FD_EPOLL };
struct ker_fd {
    int native, host;
    enum ker_fd_kind kind;
    atomic_uint references, turn;
};
struct ker_fd *ker_fd_get(int fd);
long ker_fd_put(struct ker_fd *entry);
/* Export consumes the native fd and optional private host epoll fd on all
 * paths. A real host placeholder reserves the returned application fd. */
int ker_fd_export(int native, enum ker_fd_kind kind, int host, int flags,
    int minimum, int fixed);
int ker_fd_close(int fd);
int ker_fd_dup_host(int oldfd, int newfd, int flags);
void ker_fd_close_all(void);
bool ker_native_ready(void);
#endif
