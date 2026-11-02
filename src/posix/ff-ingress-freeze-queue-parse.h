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

#endif
