/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_LKL_KER_TCP_EVENT_H
#define _ASM_LKL_KER_TCP_EVENT_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KER_TCP_EVENT_VERSION 2U
#define KER_TCP_EVENT_IOCTL_MAGIC 0xceU

#define KER_TCP_EVENT_READ_AVAILABLE_VALID (1U << 0)
#define KER_TCP_EVENT_WRITE_ACCOUNTING_VALID (1U << 1)
#define KER_TCP_EVENT_HARD_ERROR_VALID (1U << 2)
#define KER_TCP_EVENT_VALIDITY_MASK 0x7U

#define KER_TCP_EVENT_LISTENER (1U << 0)
#define KER_TCP_EVENT_ERROR_QUEUE_ONLY (1U << 1)
#define KER_TCP_EVENT_READ_SHUTDOWN (1U << 2)
#define KER_TCP_EVENT_WRITE_SHUTDOWN (1U << 3)
#define KER_TCP_EVENT_FLAGS_MASK 0xfU

/* Fixed 48-byte record. Values use native-endian ABI. Readiness, counters,
 * hard-error, and error-queue fields are nonconsuming but sampled separately. */
struct ker_tcp_event_snapshot {
	__u32 version;
	__u32 size;
	__u32 events;
	__u32 validity;
	__u16 family;
	__u16 type;
	__u16 protocol;
	__u16 reserved16;
	__s64 read_available;
	__s64 write_accounting_space;
	__s32 pending_hard_error;
	__u32 flags;
};

/* The query is private to ker-posix: target_fd is the LKL fd held by its
 * fd-table reference, and is never sent to the socket-broker client. */
struct ker_tcp_event_query {
	__u32 version;
	__u32 size;
	__s32 target_fd;
	__u32 reserved;
	struct ker_tcp_event_snapshot snapshot;
};

#define KER_TCP_EVENT_SNAPSHOT \
	_IOWR(KER_TCP_EVENT_IOCTL_MAGIC, 2, struct ker_tcp_event_query)

#endif /* _ASM_LKL_KER_TCP_EVENT_H */
