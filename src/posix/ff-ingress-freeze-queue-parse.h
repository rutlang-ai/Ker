#ifndef KER_FF_INGRESS_FREEZE_QUEUE_PARSE_H
#define KER_FF_INGRESS_FREEZE_QUEUE_PARSE_H

#include "ff-ingress-freeze-queue.h"

#include <stddef.h>
#include <stdint.h>

int ker_ff_ingress_parse_notification(const void *bytes, size_t length,
				      uint32_t queue_number,
				      uint32_t local_address,
				      uint16_t local_port,
				      struct ker_ff_ingress_packet *packet);
/* Returns 1 for the exact outstanding verdict ACK, 0 for a valid unrelated
 * message, or a negative errno for malformed/misdirected data. */
int ker_ff_ingress_parse_verdict_ack(const void *bytes, size_t length,
				     size_t sender_length, uint16_t sender_family,
				     uint32_t sender_pid, uint32_t sender_groups,
				     uint32_t portid, uint32_t sequence,
				     uint16_t request_type, uint16_t request_flags,
				     uint32_t request_length, int *ack_error);

#endif
