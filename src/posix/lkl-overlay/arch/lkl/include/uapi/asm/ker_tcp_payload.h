/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_LKL_KER_TCP_PAYLOAD_H
#define _ASM_LKL_KER_TCP_PAYLOAD_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KER_TCP_PAYLOAD_VERSION 1U
#define KER_TCP_PAYLOAD_IOCTL_MAGIC 0xceu

/* Private LKL control request. The mark is supplied by Ker's authenticated
 * broker adapter, never by the public socket-broker SDK. */
struct ker_tcp_payload_request {
	__u32 version;
	__u32 mark;
	__u32 max_sockets;
	__u32 reserved;
	__u64 payload_bytes;
	__u64 sampled_sockets;
};

#define KER_TCP_PAYLOAD_SNAPSHOT \
	_IOWR(KER_TCP_PAYLOAD_IOCTL_MAGIC, 1, struct ker_tcp_payload_request)

#endif /* _ASM_LKL_KER_TCP_PAYLOAD_H */
