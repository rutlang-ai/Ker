#ifndef KER_RX_DECISION_SHUTDOWN_FORMAT_H
#define KER_RX_DECISION_SHUTDOWN_FORMAT_H

#include "rx-decision-consumer.h"

#include <errno.h>
#include <stdio.h>
#include <stddef.h>

/* Bounded below PIPE_BUF for one atomic startup-status write. */
#define KER_RX_DECISION_SHUTDOWN_LINE_BYTES 768

static inline int ker_rx_decision_format_shutdown_line(
    char line[KER_RX_DECISION_SHUTDOWN_LINE_BYTES],
    const struct ker_rx_decision_shutdown_receipt *receipt)
{
    static const char hex[] = "0123456789abcdef";
    char record_hex[KER_RX_DECISION_SETTLED_RECORD_BYTES * 2 + 1];
    char nonce_hex[KER_RX_DECISION_NONCE_BYTES * 2 + 1];
    for (size_t i = 0; i < sizeof(receipt->record); ++i) {
        record_hex[2 * i] = hex[receipt->record[i] >> 4];
        record_hex[2 * i + 1] = hex[receipt->record[i] & 0xf];
    }
    record_hex[sizeof(record_hex) - 1] = '\0';
    for (size_t i = 0; i < sizeof(receipt->nonce); ++i) {
        nonce_hex[2 * i] = hex[receipt->nonce[i] >> 4];
        nonce_hex[2 * i + 1] = hex[receipt->nonce[i] & 0xf];
    }
    nonce_hex[sizeof(nonce_hex) - 1] = '\0';
    int length = snprintf(line, KER_RX_DECISION_SHUTDOWN_LINE_BYTES,
        "KER_C31_SHUTDOWN {\"record_hex\":\"%s\",\"worker_pid\":%u,\"worker_uid\":%u,\"worker_gid\":%u,\"worker_start_ticks\":%llu,\"supervisor_pid\":%u,\"supervisor_uid\":%u,\"supervisor_gid\":%u,\"supervisor_start_ticks\":%llu,\"nonce\":\"%s\",\"epoch\":%llu,\"last_packet_id\":%llu,\"last_result_id\":%llu,\"outstanding_count\":%u,\"status\":%d}\n",
        record_hex, receipt->worker_pid, receipt->worker_uid, receipt->worker_gid,
        (unsigned long long)receipt->worker_start_ticks, receipt->supervisor_pid,
        receipt->supervisor_uid, receipt->supervisor_gid,
        (unsigned long long)receipt->supervisor_start_ticks, nonce_hex,
        (unsigned long long)receipt->epoch,
        (unsigned long long)receipt->last_packet_id,
        (unsigned long long)receipt->last_result_id,
        receipt->outstanding_count, receipt->status);
    if (length <= 0 || (size_t)length >= KER_RX_DECISION_SHUTDOWN_LINE_BYTES)
        return -EOVERFLOW;
    return length;
}

#endif
