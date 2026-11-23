/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_POSIX_SYSCALL_RESULT_H
#define KER_POSIX_SYSCALL_RESULT_H
#include <errno.h>

/* Imported Linux syscalls return negative errno values. Successful calls do
 * not change host errno. Linux/LKL errno numbers share the Linux host ABI;
 * unlike FreeBSD, they require no numeric remapping. */
static inline long ker_native_result(long value)
{
    if (value < 0) { errno = (int)-value; return -1; }
    return value;
}
#endif
