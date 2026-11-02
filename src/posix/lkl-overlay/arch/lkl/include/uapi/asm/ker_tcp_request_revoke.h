/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_LKL_KER_TCP_REQUEST_REVOKE_H
#define _ASM_LKL_KER_TCP_REQUEST_REVOKE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define KER_TCP_REQUEST_REVOKE_VERSION 1U
#define KER_TCP_REQUEST_REVOKE_IOCTL_MAGIC 0xcfU

/* Private LKL request. A trusted privileged caller supplies the owner mark;
 * this adapter is not bound to a public socket-broker capability. Ports
 * and address bytes use network byte order. IPv4 addresses occupy the first
 * four bytes and require the remaining twelve bytes to be zero. */
struct ker_tcp_request_revoke_request {
	__u32 version;
	__u32 flags;
	__u32 mark;
	__u32 family;
	__be16 local_port;
	__be16 remote_port;
	__u32 ifindex;
	__u8 local_address[16];
	__u8 remote_address[16];
	__u32 request_cookie[2];
	__u32 listener_cookie[2];
};

#define KER_TCP_REQUEST_REVOKE \
	_IOW(KER_TCP_REQUEST_REVOKE_IOCTL_MAGIC, 1, \
	     struct ker_tcp_request_revoke_request)

#endif /* _ASM_LKL_KER_TCP_REQUEST_REVOKE_H */
