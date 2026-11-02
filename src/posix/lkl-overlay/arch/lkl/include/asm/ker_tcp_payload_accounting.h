/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_LKL_KER_TCP_PAYLOAD_ACCOUNTING_H
#define _ASM_LKL_KER_TCP_PAYLOAD_ACCOUNTING_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdbool.h>
#endif

#define KER_TCP_PAYLOAD_MAX_SKB_NODES_PER_SOCKET 16384U
#define KER_TCP_PAYLOAD_MAX_SKB_NODES_TOTAL 65536U

/* Count the part of one TCP skb's payload at or after snd_una. seq/end_seq
 * include SYN and FIN sequence space, while payload_len does not. Return
 * -1 for an ambiguous/malformed half-range interval; the caller maps that
 * to EPROTO. The routine deliberately knows nothing about TCP state. */
static inline int ker_tcp_payload_pending(__u32 seq, __u32 end_seq,
	__u32 snd_una, __u32 payload_len, bool syn, bool fin, __u64 *pending)
{
	__u64 expected = (__u64)payload_len + (syn ? 1 : 0) + (fin ? 1 : 0);
	__u32 sequence_length = end_seq - seq;
	__u32 payload_start = seq + (syn ? 1 : 0);
	__u32 acknowledged;

	if (!pending || expected >= 0x80000000ULL ||
	    sequence_length != (__u32)expected)
		return -1;
	/* TCP sequence comparisons are only ordered inside a half-range. */
	acknowledged = snd_una - payload_start;
	if (acknowledged == 0x80000000U)
		return -1;
	if ((__s32)(payload_start - snd_una) < 0) {
		*pending = acknowledged >= payload_len ? 0 : payload_len - acknowledged;
	} else {
		*pending = payload_len;
	}
	return 0;
}

static inline int ker_tcp_payload_accumulate(__u64 *total, __u64 payload)
{
	if (!total || ~(__u64)0 - *total < payload)
		return -1;
	*total += payload;
	return 0;
}

static inline int ker_tcp_payload_queue_node(__u32 *total, __u32 *per_socket)
{
	if (!total || !per_socket ||
	    *total >= KER_TCP_PAYLOAD_MAX_SKB_NODES_TOTAL ||
	    *per_socket >= KER_TCP_PAYLOAD_MAX_SKB_NODES_PER_SOCKET)
		return -1;
	++*total;
	++*per_socket;
	return 0;
}

#endif /* _ASM_LKL_KER_TCP_PAYLOAD_ACCOUNTING_H */
