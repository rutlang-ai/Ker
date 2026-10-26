#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static long finish_transfer(struct ker_fd *input, struct ker_fd *output, long result)
{
    ker_fd_put(input); ker_fd_put(output);
    if (result == -EPIPE) pthread_kill(pthread_self(), SIGPIPE);
    return ker_native_result(result);
}
/* Neither kernel can consume a descriptor from the other one's file table.
 * Reject the crossing before changing offsets or accepting any bytes. */
static int transfer_owner(int in, int out, struct ker_fd **input, struct ker_fd **output)
{
    *input = ker_fd_get(in); *output = ker_fd_get(out);
    if (!!*input != !!*output) {
        int host = *input ? out : in;
        int error = syscall(SYS_fcntl, host, F_GETFD) < 0 ? errno : EOPNOTSUPP;
        ker_fd_put(*input); ker_fd_put(*output);
        errno = error; return -1;
    }
    return *input ? 1 : 0;
}
ssize_t sendfile(int out, int in, off_t *offset, size_t count)
{
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_sendfile, out, in, offset, count);
    return finish_transfer(input, output, lkl_sys_sendfile(output->native, input->native, (void *)offset, count));
}
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux sendfile64 offset ABI");
extern __typeof(sendfile64) sendfile64 __attribute__((alias("sendfile")));
ssize_t splice(int in, loff_t *in_offset, int out, loff_t *out_offset, size_t count, unsigned flags)
{
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_splice, in, in_offset, out, out_offset, count, flags);
    return finish_transfer(input, output, lkl_sys_splice(input->native, (void *)in_offset, output->native, (void *)out_offset, count, flags));
}
ssize_t copy_file_range(int in, off64_t *in_offset, int out, off64_t *out_offset, size_t count, unsigned flags)
{
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_copy_file_range, in, in_offset, out, out_offset, count, flags);
    return finish_transfer(input, output, lkl_sys_copy_file_range(input->native, (void *)in_offset, output->native, (void *)out_offset, count, flags));
}
ssize_t tee(int in, int out, size_t count, unsigned flags)
{
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_tee, in, out, count, flags);
    return finish_transfer(input, output, lkl_sys_tee(input->native, output->native, count, flags));
}
ssize_t vmsplice(int fd, const struct iovec *vectors, size_t count, unsigned flags)
{
    struct ker_fd *entry = ker_fd_get(fd);
    if (!entry) return syscall(SYS_vmsplice, fd, vectors, count, flags);
    return finish_transfer(entry, NULL, lkl_sys_vmsplice(entry->native, (void *)vectors, count, flags));
}
