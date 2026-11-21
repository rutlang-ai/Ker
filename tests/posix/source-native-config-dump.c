#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_conf_file.h>
#include <ngx_cycle.h>
#include "source-native-ini.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ker_source_snapshot_test_dump_hash(ngx_cycle_t *cycle, uint8_t digest[32]);
int ker_source_snapshot_test_abi_check(
    const struct ker_source_native_ini_cycle_snapshot *snapshot);
int ker_source_snapshot_test_ini_hash(const char *bytes, size_t length,
    uint8_t digest[32]);

#define CHECK(test) do { \
    if (!(test)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #test); \
        return 1; \
    } \
} while (0)

static int
abi_controls(void)
{
    struct ker_source_native_ini_cycle_snapshot snapshot, before;
    memset(&snapshot, 0xa5, sizeof(snapshot));
    snapshot.version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION + 1;
    snapshot.size = sizeof(snapshot);
    before = snapshot;
    if (ker_source_snapshot_test_abi_check(&snapshot) != -EPROTO ||
        memcmp(&snapshot, &before, sizeof(snapshot)) != 0) return 0;
    snapshot = before;
    snapshot.version = KER_SOURCE_NATIVE_INI_SNAPSHOT_VERSION;
    snapshot.size--;
    before = snapshot;
    return ker_source_snapshot_test_abi_check(&snapshot) == -EPROTO &&
        memcmp(&snapshot, &before, sizeof(snapshot)) == 0;
}

#if !NGX_DEBUG
int
main(void)
{
    uint8_t digest[32];
    CHECK(abi_controls());
    CHECK(ker_source_snapshot_test_dump_hash(NULL, digest) != 0);
    puts("PASS: config-dump snapshot explicitly unsupported without NGX_DEBUG");
    return 0;
}
#else
static void
buffer_set(ngx_buf_t *buffer, const char *bytes, size_t length)
{
    memset(buffer, 0, sizeof(*buffer));
    buffer->start = (u_char *)bytes;
    buffer->pos = (u_char *)bytes;
    buffer->last = (u_char *)bytes + length;
    buffer->end = (u_char *)bytes + length;
}

static int
ini_vector(uint8_t digest[32])
{
    static const char ini[] =
        "[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n"
        "[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n"
        "file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n"
        "fstack_log_level=0\n[port0]\nlcore_list=1\n";
    char captured[KER_SOURCE_NATIVE_INI_BYTES_MAX];
    size_t captured_length = 0;
    struct ker_source_native_ini config = {0};
    FILE *file = fmemopen((void *)ini, sizeof(ini) - 1, "r");
    if (!file) return -1;
    int result = ker_source_native_ini_parse_file_capture(file,
        ker_source_native_ini_parse, &config, captured, sizeof(captured),
        &captured_length);
    if (!result) result = ker_source_native_ini_finish(&config,
        "/tmp/native/fstack.conf");
    if (!result) result = ker_source_snapshot_test_ini_hash(captured,
        captured_length, digest);
    if (fclose(file) != 0 && !result) result = -1;
    return result;
}

int
main(void)
{
    static const char main_name[] = "/tmp/ngx_rt01.conf";
    static const char mime_name[] = "/usr/local/nginx_fstack/conf/mime.types";
    static const char main_bytes[] = "worker_processes 1;\ninclude /usr/local/nginx_fstack/conf/mime.types;\n";
    static const char mime_bytes[] = "types { text/plain txt; }\n";
    ngx_cycle_t cycle;
    ngx_conf_dump_t entries[2];
    ngx_buf_t buffers[2];
    uint8_t first[32], second[32];
    static const uint8_t expected_config[32] = {
        0xea,0x21,0xde,0x9a,0x87,0x56,0x9f,0x24,0xe0,0x5f,0x5f,0xe6,0xa5,0x7b,0xcd,0x34,
        0x56,0x5f,0x7a,0x01,0xde,0x4f,0x7d,0xb2,0xec,0xe3,0x05,0x73,0xbd,0xee,0xc1,0x83
    };
    static const uint8_t expected_ini[32] = {
        0x1e,0x9f,0xf4,0x86,0x83,0x12,0xb1,0x36,0x6c,0xbc,0x29,0xa4,0x44,0x60,0x20,0xe4,
        0x71,0x16,0xf9,0x4c,0x46,0x00,0x05,0x4c,0x92,0x16,0xdb,0x2d,0xc9,0x60,0x5c,0xbf
    };

    CHECK(abi_controls());

    memset(&cycle, 0, sizeof(cycle));
    memset(entries, 0, sizeof(entries));
    buffer_set(&buffers[0], main_bytes, sizeof(main_bytes) - 1);
    buffer_set(&buffers[1], mime_bytes, sizeof(mime_bytes) - 1);
    entries[0].name.data = (u_char *)main_name;
    entries[0].name.len = sizeof(main_name) - 1;
    entries[0].buffer = &buffers[0];
    entries[1].name.data = (u_char *)mime_name;
    entries[1].name.len = sizeof(mime_name) - 1;
    entries[1].buffer = &buffers[1];
    cycle.conf_file.data = (u_char *)main_name;
    cycle.conf_file.len = sizeof(main_name) - 1;
    cycle.config_dump.elts = entries;
    cycle.config_dump.nelts = 2;
    cycle.config_dump.size = sizeof(entries[0]);

    CHECK(ker_source_snapshot_test_dump_hash(&cycle, first) == 0);
    CHECK(memcmp(first, expected_config, sizeof(first)) == 0);
    CHECK(ini_vector(second) == 0);
    CHECK(memcmp(second, expected_ini, sizeof(second)) == 0);
    char changed_main[sizeof(main_bytes)];
    memcpy(changed_main, main_bytes, sizeof(main_bytes));
    changed_main[0] = 'W';
    buffer_set(&buffers[0], changed_main, sizeof(changed_main) - 1);
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) == 0);
    CHECK(memcmp(first, second, sizeof(first)) != 0);

    buffer_set(&buffers[0], main_bytes, sizeof(main_bytes) - 1);
    buffers[0].last--;
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) != 0);
    buffer_set(&buffers[0], main_bytes, sizeof(main_bytes) - 1);
    cycle.config_dump.nelts = 1;
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) != 0);
    cycle.config_dump.nelts = 2;

    entries[1].name = entries[0].name;
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) != 0);
    entries[1].name.data = (u_char *)"/tmp/unexpected.conf";
    entries[1].name.len = sizeof("/tmp/unexpected.conf") - 1;
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) != 0);
    entries[1].name.data = (u_char *)mime_name;
    entries[1].name.len = sizeof(mime_name) - 1;

    size_t oversized_length = 256u * 1024u + 1u;
    char *oversized = malloc(oversized_length);
    CHECK(oversized != NULL);
    memset(oversized, 'x', oversized_length);
    buffer_set(&buffers[0], oversized, oversized_length);
    CHECK(ker_source_snapshot_test_dump_hash(&cycle, second) != 0);
    free(oversized);

    puts("PASS: bounded Nginx config-dump hash fixture controls");
    return 0;
}
#endif
