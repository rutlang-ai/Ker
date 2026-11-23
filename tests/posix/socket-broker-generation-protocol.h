#ifndef KER_TEST_SOCKET_BROKER_GENERATION_PROTOCOL_H
#define KER_TEST_SOCKET_BROKER_GENERATION_PROTOCOL_H

#include <stdint.h>

enum ker_test_generation_message_type {
    KER_TEST_GENERATION_READY = 1,
    KER_TEST_GENERATION_ACCEPTED = 2,
    KER_TEST_GENERATION_EXITED = 3,
    KER_TEST_GENERATION_ACK = 4,
    KER_TEST_GENERATION_FAILED = 5,
    KER_TEST_GENERATION_PAUSE_ACCEPT = 10,
    KER_TEST_GENERATION_RESUME_ACCEPT = 11,
    KER_TEST_GENERATION_RETIRE = 12
};

struct ker_test_generation_message {
    uint32_t type;
    uint32_t generation;
    uint32_t worker;
    uint32_t process_id;
    uint64_t nonce;
};

#endif
