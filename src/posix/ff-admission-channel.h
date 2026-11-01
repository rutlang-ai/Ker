#ifndef KER_FF_ADMISSION_CHANNEL_H
#define KER_FF_ADMISSION_CHANNEL_H

#include <stdint.h>
#include <sys/types.h>

#define KER_FF_ADMISSION_CHANNEL_VERSION 1U

struct ker_ff_admission_key {
	uint8_t family;
	uint8_t reserved;
	uint16_t padding;
	uint32_t source[4];
	uint32_t destination[4];
	uint16_t source_port;
	uint16_t destination_port;
};

struct ker_ff_admission_request {
	uint64_t lease;
	uint64_t command_id;
	uint64_t deadline_ns;
	uint32_t packet_id;
	struct ker_ff_admission_key key;
};

struct ker_ff_admission_result {
	uint64_t lease;
	uint64_t command_id;
	uint32_t packet_id;
	int32_t status;
	uint32_t allowed;
	uint32_t created;
};

struct ker_ff_admission_channel;

struct ker_ff_admission_map_ops {
	int (*active)(void *context);
	int (*admit)(const struct ker_ff_admission_key *key, int *created,
		     void *context);
	int (*revoke)(const struct ker_ff_admission_key *key, void *context);
	void *context;
};

enum ker_ff_admission_channel_command {
	KER_FF_ADMISSION_ADMIT = 1,
	KER_FF_ADMISSION_CANCEL = 2,
	KER_FF_ADMISSION_PREPARE_ACCEPT = 3,
	KER_FF_ADMISSION_FINALIZE = 4,
	/* Controller may issue only after positive NFQUEUE send was proven absent. */
	KER_FF_ADMISSION_CANCEL_UNSENT = 5,
	KER_FF_ADMISSION_RESULT = 0x8001,
	KER_FF_ADMISSION_CANCELLED = 0x8002,
	KER_FF_ADMISSION_PREPARED = 0x8003,
	KER_FF_ADMISSION_FINALIZED = 0x8004,
};

/* Create before starting LKL, then fork/exec the map-owner with one endpoint. */
int ker_ff_admission_channel_pair(int endpoints[2]);
int ker_ff_admission_channel_open(int fd, pid_t expected_peer,
				 uid_t expected_uid, gid_t expected_gid,
				 uint64_t lease,
				 struct ker_ff_admission_channel **channel);
void ker_ff_admission_channel_close(struct ker_ff_admission_channel *channel);

/* Controller-side nonblocking protocol. A full ADMIT send is one command; it
 * is never replayed. PREPARE_ACCEPT makes map rollback forbidden before the
 * controller submits NF_ACCEPT. FINALIZE follows a matched verdict ACK. */
int ker_ff_admission_channel_send_admit(struct ker_ff_admission_channel *channel,
					const struct ker_ff_admission_request *request);
int ker_ff_admission_channel_send_control(struct ker_ff_admission_channel *channel,
					  uint16_t command, uint64_t command_id,
					  uint32_t packet_id);
int ker_ff_admission_channel_receive(struct ker_ff_admission_channel *channel,
				     struct ker_ff_admission_result *result);

/* Call only from the original FF owner execution loop. Map callbacks run here
 * and nowhere on the LKL/controller thread. */
int ker_ff_admission_channel_owner_step(struct ker_ff_admission_channel *channel,
					const struct ker_ff_admission_map_ops *ops);

#endif
