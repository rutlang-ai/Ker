/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "host-entropy.h"
#include <errno.h>
#include <linux/random.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>
#include <lkl/linux/stat.h>

int ker_native_seed_entropy(void)
{
    /* Linux RNDADDENTROPY consumes two int fields followed by buf_size bytes.
     * Credit only entropy obtained from the host kernel's getrandom(0),
     * never time, process IDs, deterministic bytes or GRND_INSECURE output. */
    struct {
        int entropy_count, buf_size;
        unsigned char bytes[32];
    } seed = {.entropy_count = 256, .buf_size = 32};
    _Static_assert(sizeof(int) == 4 && sizeof(seed) == 40, "random ioctl ABI");
    long result = 0;
    size_t offset = 0;
    while (offset < sizeof(seed.bytes)) {
        /* Invoke the host syscall directly: the dynamically linked
         * getrandom() symbol may be supplied by the embedding application. */
        ssize_t count = syscall(SYS_getrandom, seed.bytes + offset,
                                sizeof(seed.bytes) - offset, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            result = -errno; goto out;
        }
        if (!count) { result = -EIO; goto out; }
        offset += (size_t)count;
    }
    /* This node is in LKL's private rootfs, not the host /dev. Unlink our
     * newly created node immediately after open, preserving any collision. */
    const char *path = "/ker-native-entropy";
    result = lkl_sys_mknodat(LKL_AT_FDCWD, path, LKL_S_IFCHR | 0600, (1U << 8) | 8U);
    if (result) goto out;
    long fd = lkl_sys_open(path, LKL_O_RDWR | LKL_O_CLOEXEC, 0);
    long removed = lkl_sys_unlinkat(LKL_AT_FDCWD, path, 0);
    if (fd < 0) { result = fd; goto out; }
    result = removed ? removed : lkl_sys_ioctl((unsigned int)fd, RNDADDENTROPY, (unsigned long)&seed);
    /* RNDADDENTROPY initializes an unready CRNG, but an already-ready CRNG
     * need not rekey immediately. Make this fresh host seed effective now. */
    if (!result) result = lkl_sys_ioctl((unsigned int)fd, RNDRESEEDCRNG, 0);
    long closed = lkl_sys_close((unsigned int)fd);
    if (!result) result = closed;
out:
    explicit_bzero(&seed, sizeof(seed));
    return (int)result;
}
