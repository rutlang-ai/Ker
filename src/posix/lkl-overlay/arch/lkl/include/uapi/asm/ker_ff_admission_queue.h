/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_LKL_KER_FF_ADMISSION_QUEUE_H
#define _ASM_LKL_KER_FF_ADMISSION_QUEUE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KER_FF_ADMISSION_QUEUE_VERSION 1U
#define KER_FF_ADMISSION_QUEUE_IOCTL_MAGIC 0xd1U
#define KER_FF_ADMISSION_QUEUE_NUMBER 87U
#define KER_FF_INGRESS_FREEZE_QUEUE_NUMBER 88U

/* Private privileged LKL control. The current device authenticates a trusted
 * CAP_NET_ADMIN caller; it does not bind the supplied mark to an owner token.
 * Never expose this ABI as a public socket option. */
struct ker_ff_admission_queue_control {
	__u32 version;
	__u32 flags;
	__u32 mark;
	__u32 enabled;
	__u32 expected_mark;
	__u32 reserved;
	__u64 lease;
};

#define KER_FF_ADMISSION_QUEUE_SET \
	_IOWR(KER_FF_ADMISSION_QUEUE_IOCTL_MAGIC, 1, \
	     struct ker_ff_admission_queue_control)

enum ker_ff_ingress_freeze_operation {
	KER_FF_INGRESS_FREEZE_ARM = 1,
	KER_FF_INGRESS_FREEZE_DISARM = 2,
	KER_FF_INGRESS_FREEZE_CHECK = 3,
	KER_FF_INGRESS_FREEZE_RELEASE = 4,
	KER_FF_INGRESS_FREEZE_QUARANTINE = 5,
};

/* Private CAP_NET_ADMIN control. ARM names a live raw LKL listener descriptor
 * and its observed cookie/mark. The kernel derives and retains the exact bound
 * IPv4 tuple; callers cannot choose an arbitrary filter. ARM returns a
 * monotonic deadline and tuple. DISARM returns final attempt/fault counters. */
struct ker_ff_ingress_freeze_control {
	__u32 version;
	__u32 operation;
	__s32 listener_fd;
	__u32 expected_mark;
	__u64 expected_cookie;
	__u64 lease;
	__u64 deadline_ns;
	__u32 local_address;
	__u16 local_port;
	__u16 reserved16;
	__u32 reserved32;
	__u64 attempt_count;
	__u64 expired_count;
	__u64 inventory_error_count;
};

#define KER_FF_INGRESS_FREEZE_SET \
	_IOWR(KER_FF_ADMISSION_QUEUE_IOCTL_MAGIC, 2, \
	     struct ker_ff_ingress_freeze_control)

#endif
