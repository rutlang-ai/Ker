#ifndef KER_FF_OWNER_ADMISSION_CONTROL_H
#define KER_FF_OWNER_ADMISSION_CONTROL_H

#include <stdint.h>
#include <ker/socket-broker.h>
#include "ff-admission-channel.h"

#define KER_FF_OWNER_ADMISSION_HELLO_MAGIC UINT32_C(0x4b414843)
#define KER_FF_OWNER_ADMISSION_HELLO_VERSION 1U

struct ker_ff_owner_admission_hello {
	uint32_t magic;
	uint16_t version;
	uint16_t length;
	uint64_t registration_id;
	uint32_t reserved;
} __attribute__((packed));

struct ker_ff_owner_admission_hello_reply {
	uint32_t magic;
	uint16_t version;
	uint16_t length;
	uint64_t registration_id;
	uint64_t queue_lease;
	int32_t status;
	uint32_t reserved;
} __attribute__((packed));

_Static_assert(sizeof(struct ker_ff_owner_admission_hello) == 20,
	"private admission HELLO ABI");
_Static_assert(sizeof(struct ker_ff_owner_admission_hello_reply) == 32,
	"private admission READY ABI");

struct ker_ff_owner_admission_registration {
	char endpoint_path[KER_SOCKET_BROKER_PATH_MAX + 1];
	uint64_t registration_id;
};

struct ker_ff_owner_admission_window {
	uint32_t state;
	uint32_t reserved;
	uint64_t queue_lease;
	uint64_t epoch;
	int32_t status;
	uint32_t reserved2;
};

/* Private broker protocol leaf. The caller supplies only its owner
 * capability; actor identity and mark are derived by the broker. */
int ker_socket_client_ff_owner_admission_prepare(
	struct ker_socket_client *client, int owner_cap,
	struct ker_ff_owner_admission_registration *registration);
int ker_socket_client_ff_owner_admission_window(
	struct ker_socket_client *client, int owner_cap, uint16_t operation,
	struct ker_ff_owner_admission_window *window);

/* Attach the current owner to a ready broker queue and register its owner-loop
 * map callback. This private opt-in must precede all owner socket activity. */
int ker_sb_preload_ff_owner_admission_attach(
	const struct ker_ff_admission_map_ops *ops);
int ker_sb_preload_ff_owner_admission_retire(void);
int ker_sb_preload_ff_owner_admission_rearm(void);
int ker_sb_preload_ff_owner_admission_status(
	struct ker_ff_owner_admission_window *window);

#endif
