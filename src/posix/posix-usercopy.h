#ifndef KER_POSIX_USERCOPY_H
#define KER_POSIX_USERCOPY_H
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* Copy a fixed-size kernel result to caller memory without dereferencing the
 * caller pointer in this process. Process the full prefix and report EFAULT
 * if the user range is invalid or only partially writable. */
static inline long ker_copy_to_user(void *destination, const void *source,
                                    size_t length)
{
    if ((length && !destination) || !source) return -EFAULT;
    uintptr_t base = (uintptr_t)destination;
    if (length && base > UINTPTR_MAX - (length - 1)) return -EFAULT;
    size_t copied = 0;
    while (copied < length) {
        struct iovec local = {
            .iov_base = (char *)source + copied,
            .iov_len = length - copied,
        };
        struct iovec remote = {
            .iov_base = (void *)(base + copied),
            .iov_len = length - copied,
        };
        ssize_t result;
        do {
            result = syscall(SYS_process_vm_writev, getpid(), &local, 1,
                             &remote, 1, 0);
        } while (result < 0 && errno == EINTR);
        if (result <= 0) return -EFAULT;
        copied += (size_t)result;
    }
    return 0;
}

/* Copy a bounded NUL-terminated host string without dereferencing it directly.
 * A partial copy is useful only if it already contains the terminating NUL. */
static inline long ker_copy_user_cstring(const char *source, char *destination,
                                         size_t capacity)
{
    if (!source || !destination || !capacity) return -EFAULT;
    uintptr_t base = (uintptr_t)source;
    size_t copied = 0;
    while (copied < capacity) {
        size_t amount = capacity - copied;
        if (amount > 128) amount = 128;
        if (base > UINTPTR_MAX - copied) return -EFAULT;
        uintptr_t remote_address = base + copied;
        if (remote_address > UINTPTR_MAX - (amount - 1)) {
            size_t available = (size_t)(UINTPTR_MAX - remote_address + 1);
            if (available < amount) amount = available;
        }
        if (!amount) return -EFAULT;
        struct iovec local = {.iov_base = destination + copied, .iov_len = amount};
        struct iovec remote = {.iov_base = (void *)remote_address, .iov_len = amount};
        ssize_t length;
        do {
            length = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        } while (length < 0 && errno == EINTR);
        if (length <= 0) return -EFAULT;
        char *terminator = memchr(destination + copied, '\0', (size_t)length);
        if (terminator) return (long)(terminator - destination);
        copied += (size_t)length;
        if ((size_t)length != amount) return -EFAULT;
    }
    return -ENAMETOOLONG;
}
#endif
