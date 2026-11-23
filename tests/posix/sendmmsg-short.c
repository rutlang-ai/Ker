#define _GNU_SOURCE
#include "fd-table.h"
#include "native-buffer.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <lkl.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static struct ker_fd socket_entry = {.native = 73};
static int guard_storage;
#define GUARD_TOKEN ((struct ker_native_option_guard *)&guard_storage)
static unsigned int lower_calls, guard_begins, guard_ends;

struct ker_fd *ker_fd_get(int fd)
{
    return fd == 123 ? &socket_entry : NULL;
}

bool ker_native_ready(void) { return false; }
int ker_fd_export(int native, enum ker_fd_kind kind, int host, int flags, int minimum, int fixed)
{ (void)native; (void)kind; (void)host; (void)flags; (void)minimum; (void)fixed; return -ENOSYS; }
int ker_fd_close(int fd) { (void)fd; return -1; }
int ker_fd_dup_host(int oldfd, int newfd, int flags)
{ (void)oldfd; (void)newfd; (void)flags; return -1; }
int ker_fd_host_dup(struct ker_fd *entry) { (void)entry; return -1; }
long ker_mtu_ioctl(int native_fd, unsigned long request, unsigned long argument)
{ (void)native_fd; (void)request; (void)argument; return -ENOSYS; }
long __wrap_lkl_syscall(long number, long *parameters)
{
    if (number != __lkl__NR_sendmmsg) return -ENOSYS;
    if (parameters[0] != socket_entry.native || parameters[2] != 1 ||
        !(parameters[3] & MSG_ZEROCOPY)) return -EINVAL;
    struct lkl_mmsghdr *messages = (struct lkl_mmsghdr *)parameters[1];
    ++lower_calls;
    if (lower_calls == 1) {
        messages[0].msg_len = 5; /* The first requested extent is ten bytes. */
        return 1;
    }
    messages[0].msg_len = 7;
    return 1;
}

long ker_fd_put(struct ker_fd *entry)
{
    return entry == &socket_entry ? 0 : -EINVAL;
}

int ker_native_buffer_option_begin(int native, struct ker_native_option_guard **token)
{
    if (native != socket_entry.native) return -EINVAL;
    *token = GUARD_TOKEN;
    return 0;
}

int ker_native_buffer_send_begin(int native, const struct iovec *iov, size_t count, int flags,
    struct ker_native_option_guard **token)
{
    if (native != socket_entry.native || !iov || !count || !(flags & MSG_ZEROCOPY)) return -EINVAL;
    ++guard_begins;
    *token = GUARD_TOKEN;
    return 0;
}

void ker_native_buffer_send_end(struct ker_native_option_guard *token)
{
    if (token == GUARD_TOKEN) ++guard_ends;
}

int main(void)
{
    char first[10] = {0}, second[7] = {0};
    struct iovec first_iov = {.iov_base = first, .iov_len = sizeof(first)};
    struct iovec second_iov = {.iov_base = second, .iov_len = sizeof(second)};
    struct mmsghdr messages[2] = {0};
    messages[0].msg_hdr.msg_iov = &first_iov;
    messages[0].msg_hdr.msg_iovlen = 1;
    messages[0].msg_len = 0xdecafbadU;
    messages[1].msg_hdr.msg_iov = &second_iov;
    messages[1].msg_hdr.msg_iovlen = 1;
    messages[1].msg_len = 0xdecafbadU;

    int result = sendmmsg(123, messages, 2, MSG_ZEROCOPY);
    CHECK(result == 1);
    CHECK(lower_calls == 1);
    CHECK(messages[0].msg_len == 5);
    CHECK(messages[1].msg_len == 0xdecafbadU);
    CHECK(guard_begins == 1 && guard_ends == 1);
    puts("PASS: production sendmmsg stops after short accepted message and releases one guard");
    return 0;
}
