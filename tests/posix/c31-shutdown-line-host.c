#include "rx-decision-shutdown-format.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put_le16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put_le32(uint8_t *p, uint32_t v)
{ for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static void put_le64(uint8_t *p, uint64_t v)
{ for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }

static uint64_t number(const char *text)
{
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (end == text || *end) exit(3);
    return (uint64_t)value;
}

int main(int argc, char **argv)
{
    if (argc != 1 && argc != 12) return 2;
    struct ker_rx_decision_shutdown_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    put_le32(receipt.record, 0x4b525844);
    put_le16(receipt.record + 4, 2);
    put_le16(receipt.record + 6, 7);
    put_le32(receipt.record + 8, 64);
    put_le32(receipt.record + 12, 80);
    memset(receipt.nonce, 0xa5, sizeof(receipt.nonce));
    memcpy(receipt.record + 16, receipt.nonce, sizeof(receipt.nonce));
    uint64_t epoch = UINT64_MAX, packet_id = UINT64_MAX;
    put_le64(receipt.record + 32, epoch);
    put_le64(receipt.record + 48, 3);
    put_le64(receipt.record + 64, packet_id);
    receipt.worker_pid = UINT32_MAX;
    receipt.worker_uid = UINT32_MAX;
    receipt.worker_gid = UINT32_MAX;
    receipt.worker_start_ticks = UINT64_MAX;
    receipt.supervisor_pid = UINT32_MAX;
    receipt.supervisor_uid = UINT32_MAX;
    receipt.supervisor_gid = UINT32_MAX;
    receipt.supervisor_start_ticks = UINT64_MAX;
    receipt.epoch = UINT64_MAX;
    receipt.last_packet_id = UINT64_MAX;
    receipt.last_result_id = UINT64_MAX;
    if (argc == 12) {
        receipt.worker_pid = (uint32_t)number(argv[1]);
        receipt.worker_uid = (uint32_t)number(argv[2]);
        receipt.worker_gid = (uint32_t)number(argv[3]);
        receipt.worker_start_ticks = number(argv[4]);
        receipt.supervisor_pid = (uint32_t)number(argv[5]);
        receipt.supervisor_uid = (uint32_t)number(argv[6]);
        receipt.supervisor_gid = (uint32_t)number(argv[7]);
        receipt.supervisor_start_ticks = number(argv[8]);
        epoch = number(argv[9]);
        packet_id = number(argv[10]);
        if (strlen(argv[11]) != 32) return 4;
        for (size_t i = 0; i < 16; ++i) {
            unsigned byte;
            if (sscanf(argv[11] + 2 * i, "%2x", &byte) != 1) return 4;
            receipt.nonce[i] = (uint8_t)byte;
        }
        memcpy(receipt.record + 16, receipt.nonce, sizeof(receipt.nonce));
        put_le64(receipt.record + 32, epoch);
        put_le64(receipt.record + 64, packet_id);
        receipt.epoch = epoch;
        receipt.last_packet_id = packet_id;
        receipt.last_result_id = packet_id;
    }
    receipt.outstanding_count = 0;
    receipt.status = 0;
    char line[KER_RX_DECISION_SHUTDOWN_LINE_BYTES];
    int length = ker_rx_decision_format_shutdown_line(line, &receipt);
    if (length <= 0 || (size_t)length >= sizeof(line) ||
            (argc == 1 && length >= 640))
        return 1;
    return fwrite(line, 1, (size_t)length, stdout) == (size_t)length ? 0 : 2;
}
