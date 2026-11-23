#include "nginx-source-bootstrap.h"

#include <stdio.h>

static int check(int condition, const char *name)
{
    if (!condition) fprintf(stderr, "source bootstrap v4: failed: %s\n", name);
    return condition ? 0 : 1;
}

int main(void)
{
    int failures = 0;
    struct ker_source_native_ini_cycle_snapshot snapshot = {
        .version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION,
        .size = sizeof(snapshot),
        .adapter_cycle_serial = 9,
        .cycle_identity = 0x12345000,
    };
    memset(snapshot.config_sha256, 0x31, sizeof(snapshot.config_sha256));
    memset(snapshot.ini_sha256, 0x72, sizeof(snapshot.ini_sha256));
    struct ker_nginx_source_bootstrap_record legacy = {
        .magic = KER_NGINX_SOURCE_BOOTSTRAP_MAGIC,
        .version = KER_NGINX_SOURCE_BOOTSTRAP_VERSION,
        .type = KER_NGINX_SOURCE_BOOTSTRAP_REQUEST,
        .record_bytes = sizeof(legacy),
        .role = KER_NGINX_SOURCE_ROLE_SLIM,
        .actor_pid = 101,
        .actor_tid = 102,
        .master_pid = 101,
        .launch_epoch = 77,
        .deadline_ns = 1000,
    };
    struct ker_nginx_source_bootstrap_record_v4 wire;
    memset(&wire, 0xa5, sizeof(wire));
    failures += check(sizeof(legacy) == 176 &&
        KER_NGINX_SOURCE_BOOTSTRAP_VERSION == 3, "legacy v3 layout unchanged");
    failures += check(sizeof(wire) == 264 &&
        offsetof(struct ker_nginx_source_bootstrap_record_v4, proof) == 176,
        "v4 proof is appended at byte 176");
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &wire) == 0 && wire.record.version == 4 && wire.record.record_bytes == 264 &&
        wire.proof.version == 1 && wire.proof.flags == 0 &&
        wire.proof.adapter_cycle_serial == 9 &&
        wire.proof.opaque_cycle_token == UINT64_C(0x12345000) &&
        !memcmp(wire.proof.config_sha256, snapshot.config_sha256, 32) &&
        !memcmp(wire.proof.ini_sha256, snapshot.ini_sha256, 32),
        "v4 encodes typed snapshot");
    struct ker_nginx_source_bootstrap_record expected_reply = wire.record;
    expected_reply.type = KER_NGINX_SOURCE_BOOTSTRAP_REPLY;
    expected_reply.supervisor_pid = 201;
    expected_reply.runtime_pid = 202;
    expected_reply.io_pid = 203;
    expected_reply.supervisor_start_ticks = 301;
    expected_reply.runtime_start_ticks = 302;
    expected_reply.io_start_ticks = 303;
    struct ker_nginx_source_bootstrap_record_v4 echoed = wire;
    echoed.record = expected_reply;
    failures += check(ker_nginx_source_bootstrap_v4_matches(&expected_reply,
        &wire.proof, &echoed), "v4 exact reply echo accepted");
    echoed.proof.ini_sha256[0] ^= 1;
    failures += check(!ker_nginx_source_bootstrap_v4_matches(&expected_reply,
        &wire.proof, &echoed), "v4 reply proof mutation rejected");
    echoed = wire;
    echoed.record = expected_reply;
    echoed.record.record_bytes--;
    failures += check(!ker_nginx_source_bootstrap_v4_matches(&expected_reply,
        &wire.proof, &echoed), "v4 malformed record size rejected");

    struct ker_nginx_source_bootstrap_proof proof;
    failures += check(ker_nginx_source_bootstrap_proof_from_snapshot(&snapshot,
        &proof) == 0 && ker_nginx_source_bootstrap_proof_equal(&proof, &wire.proof),
        "proof equality accepts exact cycle proof");
    struct ker_nginx_source_bootstrap_proof changed = wire.proof;
    changed.config_sha256[0] ^= 1;
    failures += check(!ker_nginx_source_bootstrap_proof_equal(&wire.proof, &changed),
        "proof equality rejects config digest mutation");
    changed = wire.proof;
    changed.ini_sha256[31] ^= 1;
    failures += check(!ker_nginx_source_bootstrap_proof_equal(&wire.proof, &changed),
        "proof equality rejects INI digest mutation");
    changed = wire.proof;
    changed.opaque_cycle_token++;
    failures += check(!ker_nginx_source_bootstrap_proof_equal(&wire.proof, &changed),
        "proof equality rejects cycle identity mutation");
    changed = wire.proof;
    changed.flags = 1;
    failures += check(!ker_nginx_source_bootstrap_proof_equal(&wire.proof, &changed),
        "proof equality rejects reserved flags");

    struct ker_nginx_source_bootstrap_record_v4 sentinel, before;
    memset(&sentinel, 0x5c, sizeof(sentinel));
    before = sentinel;
    snapshot.version++;
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &sentinel) == -EPROTO && !memcmp(&sentinel, &before, sizeof(before)),
        "wrong snapshot version rejected without output mutation");
    snapshot.version--;
    snapshot.size--;
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &sentinel) == -EPROTO && !memcmp(&sentinel, &before, sizeof(before)),
        "wrong snapshot size rejected without output mutation");
    snapshot.size++;
    snapshot.adapter_cycle_serial = 0;
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &sentinel) == -ESTALE && !memcmp(&sentinel, &before, sizeof(before)),
        "missing cycle serial rejected without output mutation");
    snapshot.adapter_cycle_serial = 9;
    memset(snapshot.config_sha256, 0, sizeof(snapshot.config_sha256));
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &sentinel) == -EPROTO && !memcmp(&sentinel, &before, sizeof(before)),
        "empty digest rejected without output mutation");
    legacy.record_bytes--;
    failures += check(ker_nginx_source_bootstrap_v4_encode(&legacy, &snapshot,
        &sentinel) == -EPROTO && !memcmp(&sentinel, &before, sizeof(before)),
        "legacy base must be exact v3/176 before shell encoding");
    return failures ? 1 : 0;
}
