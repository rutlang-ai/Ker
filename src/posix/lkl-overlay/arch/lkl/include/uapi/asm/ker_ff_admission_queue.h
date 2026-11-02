/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_LKL_KER_FF_ADMISSION_QUEUE_H
#define _ASM_LKL_KER_FF_ADMISSION_QUEUE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KER_FF_ADMISSION_QUEUE_VERSION 1U
#define KER_FF_ADMISSION_QUEUE_IOCTL_MAGIC 0xd1U
#define KER_FF_ADMISSION_QUEUE_NUMBER 87U

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

#endif
