#define _GNU_SOURCE
#include "fd-table.h"
#include "syscall-result.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <lkl.h>

#define KER_SPLICE_FLAGS (SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT)
#define KER_TRANSFER_IOV_MAX 1024
_Static_assert(sizeof(off_t) == sizeof(lkl_loff_t), "host/LKL file offset ABI");
_Static_assert(sizeof(off_t) == sizeof(lkl_off_t), "host/LKL sendfile offset ABI");
_Static_assert(sizeof(struct iovec) == sizeof(struct lkl_iovec), "host/LKL iovec ABI");
_Static_assert(sizeof(((struct iovec *)0)->iov_len) == sizeof(((struct lkl_iovec *)0)->iov_len), "host/LKL iovec length type");
_Static_assert(offsetof(struct iovec, iov_base) == offsetof(struct lkl_iovec, iov_base), "host/LKL iovec base ABI");
_Static_assert(offsetof(struct iovec, iov_len) == offsetof(struct lkl_iovec, iov_len), "host/LKL iovec length ABI");

/* LKL's NOMMU uaccess path uses memcpy and can fault the host process. Keep
 * user pointers at this boundary and use the host kernel for fault-safe copies. */
static int copy_from_user(void *destination, const void *source, size_t length)
{
    size_t copied = 0;
    while (copied < length) {
        struct iovec local = {(char *)destination + copied, length - copied};
        struct iovec remote = {(void *)((uintptr_t)source + copied), length - copied};
        ssize_t result = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) { errno = EFAULT; return -1; }
        copied += (size_t)result;
    }
    return 0;
}

static int copy_to_user(void *destination, const void *source, size_t length)
{
    size_t copied = 0;
    while (copied < length) {
        struct iovec local = {(char *)source + copied, length - copied};
        struct iovec remote = {(void *)((uintptr_t)destination + copied), length - copied};
        ssize_t result = syscall(SYS_process_vm_writev, getpid(), &local, 1, &remote, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) { errno = EFAULT; return -1; }
        copied += (size_t)result;
    }
    return 0;
}

static long finish_transfer(struct ker_fd *input, struct ker_fd *output, long result)
{
    ker_fd_put(input); ker_fd_put(output);
    if (result == -EPIPE) pthread_kill(pthread_self(), SIGPIPE);
    return ker_native_result(result);
}
static void release_transfer(struct ker_fd *input, struct ker_fd *output, long result)
{
    ker_fd_put(input); ker_fd_put(output);
    if (result == -EPIPE) pthread_kill(pthread_self(), SIGPIPE);
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
    lkl_off_t position;
    if (offset && copy_from_user(&position, offset, sizeof(position)) < 0)
        return finish_transfer(input, output, -EFAULT);
    long result = lkl_sys_sendfile(output->native, input->native, offset ? &position : NULL, count);
    if (offset && copy_to_user(offset, &position, sizeof(position)) < 0) {
        release_transfer(input, output, result);
        errno = EFAULT; return -1;
    }
    return finish_transfer(input, output, result);
}
_Static_assert(sizeof(off_t) == sizeof(off64_t), "Linux sendfile64 offset ABI");
extern __typeof(sendfile64) sendfile64 __attribute__((alias("sendfile")));
ssize_t splice(int in, loff_t *in_offset, int out, loff_t *out_offset, size_t count, unsigned flags)
{
    if (!count) return 0;
    if (flags & ~KER_SPLICE_FLAGS) { errno = EINVAL; return -1; }
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_splice, in, in_offset, out, out_offset, count, flags);
    lkl_loff_t input_position, output_position;
    if (out_offset && copy_from_user(&output_position, out_offset, sizeof(output_position)) < 0)
        return finish_transfer(input, output, -EFAULT);
    if (in_offset && copy_from_user(&input_position, in_offset, sizeof(input_position)) < 0)
        return finish_transfer(input, output, -EFAULT);
    long result = lkl_sys_splice(input->native, in_offset ? &input_position : NULL,
        output->native, out_offset ? &output_position : NULL, count, flags);
    if (result >= 0) {
        if (out_offset && copy_to_user(out_offset, &output_position, sizeof(output_position)) < 0)
            result = -EFAULT;
        else if (in_offset && copy_to_user(in_offset, &input_position, sizeof(input_position)) < 0)
            result = -EFAULT;
    }
    return finish_transfer(input, output, result);
}
ssize_t copy_file_range(int in, off64_t *in_offset, int out, off64_t *out_offset, size_t count, unsigned flags)
{
    struct ker_fd *input, *output;
    int owner = transfer_owner(in, out, &input, &output);
    if (owner < 0) return -1;
    if (!owner) return syscall(SYS_copy_file_range, in, in_offset, out, out_offset, count, flags);
    lkl_loff_t input_position, output_position;
    if (in_offset && copy_from_user(&input_position, in_offset, sizeof(input_position)) < 0)
        return finish_transfer(input, output, -EFAULT);
    if (out_offset && copy_from_user(&output_position, out_offset, sizeof(output_position)) < 0)
        return finish_transfer(input, output, -EFAULT);
    long result = lkl_sys_copy_file_range(input->native, in_offset ? &input_position : NULL,
        output->native, out_offset ? &output_position : NULL, count, flags);
    if (result > 0) {
        if (in_offset && copy_to_user(in_offset, &input_position, sizeof(input_position)) < 0)
            result = -EFAULT;
        else if (out_offset && copy_to_user(out_offset, &output_position, sizeof(output_position)) < 0)
            result = -EFAULT;
    }
    return finish_transfer(input, output, result);
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
    if (flags & ~KER_SPLICE_FLAGS) return finish_transfer(entry, NULL, -EINVAL);
    if (count > KER_TRANSFER_IOV_MAX) return finish_transfer(entry, NULL, -EINVAL);
    if (!count) return finish_transfer(entry, NULL, lkl_sys_vmsplice(entry->native, NULL, 0, flags));
    struct lkl_iovec *local_vectors = malloc(count * sizeof(*local_vectors));
    if (!local_vectors) return finish_transfer(entry, NULL, -ENOMEM);
    if (copy_from_user(local_vectors, vectors, count * sizeof(*vectors)) < 0) {
        free(local_vectors);
        return finish_transfer(entry, NULL, -EFAULT);
    }
    /* Keep original payload addresses; upstream may pin their pages. */
    long result = lkl_sys_vmsplice(entry->native, local_vectors, count, flags);
    free(local_vectors);
    return finish_transfer(entry, NULL, result);
}
