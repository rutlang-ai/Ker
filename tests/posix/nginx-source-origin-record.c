#include "nginx-source-origin.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(test) do { \
    if (!(test)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #test); \
        return 1; \
    } \
} while (0)

static void
fill_snapshot(struct ker_source_native_ini_cycle_snapshot *snapshot)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    snapshot->size = sizeof(*snapshot);
    snapshot->adapter_cycle_serial = 19;
    snapshot->cycle_identity = (uintptr_t)0x12345678;
    memset(snapshot->config_sha256, 0x31, sizeof(snapshot->config_sha256));
    memset(snapshot->ini_sha256, 0x52, sizeof(snapshot->ini_sha256));
}

int
main(void)
{
    struct ker_source_native_ini_cycle_snapshot snapshot, before_snapshot;
    struct ker_nginx_source_origin_record request = {0}, ack, expected;

    CHECK(sizeof(request) == 208);
    CHECK(offsetof(struct ker_nginx_source_origin_record, proof_version) == 120);
    fill_snapshot(&snapshot);
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == 0);
    CHECK(ker_nginx_source_origin_snapshot_status(-ENOTSUP, &snapshot) == -ENOTSUP);
    CHECK(ker_nginx_source_origin_snapshot_status(-ESTALE, &snapshot) == -ESTALE);

    before_snapshot = snapshot;
    snapshot.version++;
    struct ker_source_native_ini_cycle_snapshot invalid_snapshot = snapshot;
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -EPROTO);
    CHECK(memcmp(&snapshot, &invalid_snapshot, sizeof(snapshot)) == 0);
    snapshot = before_snapshot;
    snapshot.size--;
    invalid_snapshot = snapshot;
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -EPROTO);
    CHECK(memcmp(&snapshot, &invalid_snapshot, sizeof(snapshot)) == 0);
    snapshot = before_snapshot;
    snapshot.adapter_cycle_serial = 0;
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -ESTALE);
    snapshot = before_snapshot;
    snapshot.cycle_identity = 0;
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -ESTALE);
    snapshot = before_snapshot;
    memset(snapshot.config_sha256, 0, sizeof(snapshot.config_sha256));
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -EPROTO);
    snapshot = before_snapshot;
    memset(snapshot.ini_sha256, 0, sizeof(snapshot.ini_sha256));
    CHECK(ker_nginx_source_origin_snapshot_status(0, &snapshot) == -EPROTO);
    snapshot = before_snapshot;

    request.magic = KER_NGINX_SOURCE_ORIGIN_MAGIC;
    request.version = KER_NGINX_SOURCE_ORIGIN_VERSION;
    request.type = KER_NGINX_SOURCE_ORIGIN_REQUEST;
    request.record_bytes = sizeof(request);
    CHECK(ker_nginx_source_origin_bind_snapshot(&request, &snapshot) == 0);
    CHECK(ker_nginx_source_origin_proof_matches(&request, &snapshot) == 0);
    expected = request;
    expected.type = KER_NGINX_SOURCE_ORIGIN_ACK;
    ack = expected;
    CHECK(memcmp(&expected, &ack, sizeof(ack)) == 0);
    ack.config_sha256[0] ^= 1;
    CHECK(memcmp(&expected, &ack, sizeof(ack)) != 0);

    struct ker_nginx_source_origin_record malformed = request;
    malformed.proof_version++;
    CHECK(ker_nginx_source_origin_proof_matches(&malformed, &snapshot) == -EPROTO);
    malformed = request;
    malformed.proof_flags = 1;
    CHECK(ker_nginx_source_origin_proof_matches(&malformed, &snapshot) == -EPROTO);
    malformed = request;
    malformed.record_bytes--;
    CHECK(ker_nginx_source_origin_proof_matches(&malformed, &snapshot) == -EPROTO);
    malformed = request;
    malformed.magic++;
    CHECK(ker_nginx_source_origin_proof_matches(&malformed, &snapshot) == -EPROTO);
    malformed = request;
    malformed.type = KER_NGINX_SOURCE_ORIGIN_ACK;
    CHECK(ker_nginx_source_origin_proof_matches(&malformed, &snapshot) == -EPROTO);

    struct ker_nginx_source_origin_record untouched = request;
    snapshot = before_snapshot;
    snapshot.version++;
    CHECK(ker_nginx_source_origin_bind_snapshot(&request, &snapshot) == -EPROTO);
    CHECK(memcmp(&request, &untouched, sizeof(request)) == 0);
    snapshot = before_snapshot;
    snapshot.adapter_cycle_serial++;
    CHECK(ker_nginx_source_origin_proof_matches(&request, &snapshot) == -ESTALE);
    snapshot = before_snapshot;
    snapshot.cycle_identity++;
    CHECK(ker_nginx_source_origin_proof_matches(&request, &snapshot) == -ESTALE);
    snapshot = before_snapshot;
    snapshot.config_sha256[0] ^= 1;
    CHECK(ker_nginx_source_origin_proof_matches(&request, &snapshot) == -ESTALE);
    snapshot = before_snapshot;
    snapshot.ini_sha256[0] ^= 1;
    CHECK(ker_nginx_source_origin_proof_matches(&request, &snapshot) == -ESTALE);

    puts("PASS: v2 origin cycle-proof ABI, status, binding and exact-echo controls");
    return 0;
}
