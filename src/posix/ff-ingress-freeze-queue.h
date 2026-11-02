#ifndef KER_FF_INGRESS_FREEZE_QUEUE_H
#define KER_FF_INGRESS_FREEZE_QUEUE_H

#include <stdint.h>

/* Private LKL runtime interface. Not installed or exported as an SDK API. */
struct ker_ff_ingress_freeze_queue;
struct ker_ff_ingress_packet {
	uint64_t lease;
	uint64_t deadline_ns;
	uint32_t id;
	uint32_t local_address;
	uint32_t remote_address;
	uint16_t local_port;
	uint16_t remote_port;
};

int ker_ff_ingress_freeze_queue_start(int listener_native_fd,
				 uint32_t owner_mark,
				 uint64_t listener_cookie,
				 struct ker_ff_ingress_freeze_queue **queue);
uint64_t ker_ff_ingress_freeze_queue_lease(
				 const struct ker_ff_ingress_freeze_queue *queue);
/* Serialized LKL barrier/inventory check; call before every held-skb verdict. */
int ker_ff_ingress_freeze_queue_check(
	struct ker_ff_ingress_freeze_queue *queue);
int ker_ff_ingress_freeze_queue_receive(struct ker_ff_ingress_freeze_queue *queue,
				   struct ker_ff_ingress_packet *packet,
				   unsigned int timeout_ms);
/* After the coordinator's successful selector cutover, DISARM closes the
 * ingress gate. Drain reads any already-enqueued original packet and proves
 * the bounded q88 notification socket empty before ACCEPT/close. */
int ker_ff_ingress_freeze_queue_disarm(struct ker_ff_ingress_freeze_queue *queue);
int ker_ff_ingress_freeze_queue_drain(struct ker_ff_ingress_freeze_queue *queue,
				      struct ker_ff_ingress_packet *packet);
/* Disable only the exact ingress lease. Any queued packet remains the original
 * skb and must be explicitly accepted/rejected before queue close. */
int ker_ff_ingress_freeze_queue_accept(struct ker_ff_ingress_freeze_queue *queue,
				 uint64_t lease, uint64_t deadline_ns,
				 uint32_t packet_id, int *sent_to_kernel);
/* Explicit fail-closed cleanup after uncertainty: queue close drops its held
 * skb entries and leaves the kernel lease/gate allocated; no healthy recovery
 * or subsequent lease reuse is implied. */
int ker_ff_ingress_freeze_queue_quarantine(
	struct ker_ff_ingress_freeze_queue **queue);
/* Close is allowed only after exact lease disarm and all delivered packet IDs
 * have matched verdict acknowledgements. */
int ker_ff_ingress_freeze_queue_close(struct ker_ff_ingress_freeze_queue *queue);

#endif
