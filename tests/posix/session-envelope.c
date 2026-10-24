#include "io-session.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    struct ker_session_message identity = {.magic = KER_SESSION_MAGIC, .version = KER_SESSION_VERSION,
        .command = KER_SESSION_PROBE, .sequence = 1, .session = 123, .epoch = 9,
        .slot = 2, .generation = 1, .process = 3, .status = -EINPROGRESS};
    struct ker_session_probe request = {.identity = identity};
    CHECK(!ker_session_probe_check(&request, &identity, 0));
    CHECK(ker_session_probe_check(&request, &identity, 1) == -ESTALE);
    const size_t offsets[] = {
        offsetof(struct ker_session_message, magic), offsetof(struct ker_session_message, version),
        offsetof(struct ker_session_message, command), offsetof(struct ker_session_message, sequence),
        offsetof(struct ker_session_message, session), offsetof(struct ker_session_message, epoch),
        offsetof(struct ker_session_message, generation), offsetof(struct ker_session_message, process),
        offsetof(struct ker_session_message, token), offsetof(struct ker_session_message, slot)};
    for (unsigned field = 0; field < sizeof(offsets) / sizeof(offsets[0]); field++) {
        struct ker_session_probe foreign = request;
        uint64_t value;
        unsigned char *address = (unsigned char *)&foreign.identity + offsets[field];
        memcpy(&value, address, sizeof(value)); value ^= 1;
        memcpy(address, &value, sizeof(value));
        CHECK(ker_session_probe_check(&foreign, &identity, 0) == -ESTALE);
    }
    request.identity.status = 0;
    CHECK(ker_session_probe_check(&request, &identity, 0) == -ESTALE);
    request.identity.status = -EINPROGRESS; request.responder = 1;
    CHECK(ker_session_probe_check(&request, &identity, 0) == -ESTALE);
    puts("PASS: shared control rejects foreign identities, completed requests and replayed sequences");
    return 0;
}
