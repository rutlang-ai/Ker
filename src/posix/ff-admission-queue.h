#ifndef KER_FF_ADMISSION_QUEUE_H
#define KER_FF_ADMISSION_QUEUE_H

#include <stdint.h>

/* Private LKL runtime interface. Not installed or exported as an SDK API. */
struct ker_ff_admission_queue;
struct ker_ff_admission_packet {
	uint64_t lease;
	uint64_t deadline_ns;
	uint32_t id;
	uint32_t mark;
	uint32_t local_address;
	uint32_t remote_address;
	uint16_t local_port;
	uint16_t remote_port;
	uint32_t server_sequence;
	uint8_t tcp_options_length;
	uint8_t tcp_options[40];
};

int ker_ff_admission_queue_start(uint32_t owner_mark,
				 struct ker_ff_admission_queue **queue);
uint64_t ker_ff_admission_queue_lease(
				 const struct ker_ff_admission_queue *queue);
int ker_ff_admission_queue_receive(struct ker_ff_admission_queue *queue,
				   struct ker_ff_admission_packet *packet,
				   unsigned int timeout_ms);
int ker_ff_admission_queue_verdict(struct ker_ff_admission_queue *queue,
				   uint64_t lease, uint64_t deadline_ns,
				   uint32_t packet_id, int accept,
				   int *sent_to_kernel);
#ifdef KER_C15_TEST_ACK_LOSS
/* Test-only control: close the netlink socket after a full NF_ACCEPT send and
 * leave its ACK unread, returning -ECONNRESET with sent_to_kernel=1. */
int ker_ff_admission_queue_test_accept_unread_ack(
	struct ker_ff_admission_queue *queue, uint64_t lease, uint64_t deadline_ns,
	uint32_t packet_id, int *sent_to_kernel);
int ker_ff_admission_queue_test_drop_wrong_id(
	struct ker_ff_admission_queue *queue, uint64_t lease, uint64_t deadline_ns,
	uint32_t packet_id, int *sent_to_kernel);
#endif
/* Caller must first close the registered listener, observe request count zero,
 * and prove no queued packet/command remains. */
int ker_ff_admission_queue_disarm_after_quiescence(
	struct ker_ff_admission_queue *queue);
void ker_ff_admission_queue_close(struct ker_ff_admission_queue *queue);

#endif
