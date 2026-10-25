#include "io-session.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    CHECK(sizeof(struct ker_session_message)==128 && sizeof(struct ker_session_probe)==200);
    struct ker_session_message identity = {.magic = KER_SESSION_MAGIC, .version = KER_SESSION_VERSION,
        .command = KER_SESSION_PROBE, .sequence = 1, .session = 123, .epoch = 9,
        .slot = 2, .generation = 1, .process = 3, .status = -EINPROGRESS,
        .tx_lease_id = UINT64_C(0x8000000000000042), .rx_lease_id = 0x123456789abcdef0};
    struct ker_session_probe request = {.identity = identity};
    CHECK(!ker_session_probe_check(&request, &identity, 0));
    CHECK(ker_session_probe_check(&request, &identity, 1) == -ESTALE);
    const struct { size_t offset, width; } fields[] = {
        {offsetof(struct ker_session_message, magic), sizeof(identity.magic)},
        {offsetof(struct ker_session_message, version), sizeof(identity.version)},
        {offsetof(struct ker_session_message, command), sizeof(identity.command)},
        {offsetof(struct ker_session_message, sequence), sizeof(identity.sequence)},
        {offsetof(struct ker_session_message, session), sizeof(identity.session)},
        {offsetof(struct ker_session_message, epoch), sizeof(identity.epoch)},
        {offsetof(struct ker_session_message, generation), sizeof(identity.generation)},
        {offsetof(struct ker_session_message, process), sizeof(identity.process)},
        {offsetof(struct ker_session_message, token), sizeof(identity.token)},
        {offsetof(struct ker_session_message, slot), sizeof(identity.slot)},
        {offsetof(struct ker_session_message, capability), sizeof(identity.capability)},
        {offsetof(struct ker_session_message, tx_lease_id), sizeof(identity.tx_lease_id)},
        {offsetof(struct ker_session_message, rx_lease_id), sizeof(identity.rx_lease_id)},
        {offsetof(struct ker_session_message, packet_pool_tag), sizeof(identity.packet_pool_tag)},
        {offsetof(struct ker_session_message, packet_object_index), sizeof(identity.packet_object_index)},
        {offsetof(struct ker_session_message, packet_port), sizeof(identity.packet_port)},
        {offsetof(struct ker_session_message, packet_queue), sizeof(identity.packet_queue)}};
    for (unsigned field = 0; field < sizeof(fields) / sizeof(fields[0]); field++) {
        struct ker_session_probe foreign = request;
        unsigned char *address = (unsigned char *)&foreign.identity + fields[field].offset;
        *address ^= 1;
        CHECK(ker_session_probe_check(&foreign, &identity, 0) == -ESTALE);
    }
    request.identity.status = 0;
    CHECK(ker_session_probe_check(&request, &identity, 0) == -ESTALE);
    request.identity.status = -EINPROGRESS; request.responder = 1;
    CHECK(ker_session_probe_check(&request, &identity, 0) == -ESTALE);
    puts("PASS: shared control rejects foreign identities, completed requests and replayed sequences");
    return 0;
}
