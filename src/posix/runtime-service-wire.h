#ifndef KER_RUNTIME_SERVICE_WIRE_H
#define KER_RUNTIME_SERVICE_WIRE_H

#include <stddef.h>
#include <stdint.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "runtime service wire currently requires a little-endian host"
#endif

#define KER_RUNTIME_SERVICE_MAGIC UINT32_C(0x4b525356)
#define KER_RUNTIME_SERVICE_VERSION 1
#define KER_RUNTIME_SERVICE_NONCE_BYTES 16
#define KER_RUNTIME_SERVICE_LEASE_BYTES 16
#define KER_RUNTIME_SERVICE_TICKET_BYTES 32
#define KER_RUNTIME_SERVICE_PROFILE_BYTES 32

enum ker_runtime_service_operation {
    KER_RUNTIME_SERVICE_CLAIM = 1,
    KER_RUNTIME_SERVICE_CHECK = 2,
    KER_RUNTIME_SERVICE_RELEASE = 3
};

/* All fields are little-endian. The response status is a positive errno on
 * failure and zero on success. A request must set status to zero. */
struct __attribute__((packed)) ker_runtime_service_header {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t packet_length;
    int32_t status;
    uint64_t sequence;
    uint64_t service_epoch;
    uint8_t run_nonce[KER_RUNTIME_SERVICE_NONCE_BYTES];
    uint8_t lease_id[KER_RUNTIME_SERVICE_LEASE_BYTES];
};

struct __attribute__((packed)) ker_runtime_service_claim {
    uint8_t ticket[KER_RUNTIME_SERVICE_TICKET_BYTES];
    uint8_t profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
};

struct __attribute__((packed)) ker_runtime_service_claim_result {
    uint8_t worker_profile_hash[KER_RUNTIME_SERVICE_PROFILE_BYTES];
};

_Static_assert(sizeof(struct ker_runtime_service_header) == 64,
    "runtime service header ABI");
_Static_assert(offsetof(struct ker_runtime_service_header, run_nonce) == 32,
    "runtime service nonce offset");
_Static_assert(offsetof(struct ker_runtime_service_header, lease_id) == 48,
    "runtime service lease offset");
_Static_assert(sizeof(struct ker_runtime_service_claim) == 64,
    "runtime service claim ABI");
_Static_assert(sizeof(struct ker_runtime_service_claim_result) == 32,
    "runtime service claim result ABI");

#endif
