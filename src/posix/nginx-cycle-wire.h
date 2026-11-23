/* Private KNGC master-to-outer cycle control wire. */
#ifndef KER_NGINX_CYCLE_WIRE_H
#define KER_NGINX_CYCLE_WIRE_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#define KER_NGX_CYCLE_MAGIC UINT32_C(0x43474e4b) /* bytes "KNGC" */
#define KER_NGX_CYCLE_VERSION 1u
#define KER_NGX_CYCLE_HEADER_BYTES 64u
#define KER_NGX_CYCLE_RUNTIME_BYTES 56u
#define KER_NGX_CYCLE_WATCH_BYTES 120u
#define KER_NGX_CYCLE_MAX_SEQUENCE UINT64_MAX

enum ker_nginx_cycle_type {
    KER_NGX_CYCLE_WATCH_BOUND = 1,
    KER_NGX_CYCLE_DRAINED = 2,
    KER_NGX_CYCLE_READY = 3,
    KER_NGX_CYCLE_ERROR = 4
};

struct ker_nginx_cycle_header {
    uint16_t type;
    uint32_t total_bytes;
    int32_t status;
    uint8_t master_nonce[16];
    uint64_t master_start_ticks;
    uint64_t sequence;
    uint64_t cycle_id;
};

struct ker_nginx_cycle_runtime {
    uint8_t broker_nonce[16];
    uint64_t broker_epoch;
    uint8_t worker_profile_sha256[32];
};

static inline void
ker_nginx_cycle_put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static inline void
ker_nginx_cycle_put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i != 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static inline void
ker_nginx_cycle_put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i != 8; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static inline uint16_t
ker_nginx_cycle_get16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static inline uint32_t
ker_nginx_cycle_get32(const uint8_t *p)
{
    uint32_t value = 0;
    for (unsigned i = 0; i != 4; ++i) value |= (uint32_t)p[i] << (8 * i);
    return value;
}

static inline uint64_t
ker_nginx_cycle_get64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i != 8; ++i) value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static inline int
ker_nginx_cycle_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t value = 0;
    for (size_t i = 0; i != length; ++i) value |= bytes[i];
    return value != 0;
}

static inline int
ker_nginx_cycle_parse_hex(const char *text, uint8_t *output, size_t bytes)
{
    if (!text || !output || strlen(text) != bytes * 2) return -1;
    for (size_t i = 0; i < bytes; ++i) {
        unsigned hi, lo;
        char a = text[i * 2], b = text[i * 2 + 1];
        if (a >= '0' && a <= '9') hi = (unsigned)(a - '0');
        else if (a >= 'a' && a <= 'f') hi = (unsigned)(a - 'a') + 10;
        else return -1;
        if (b >= '0' && b <= '9') lo = (unsigned)(b - '0');
        else if (b >= 'a' && b <= 'f') lo = (unsigned)(b - 'a') + 10;
        else return -1;
        output[i] = (uint8_t)((hi << 4) | lo);
    }
    return ker_nginx_cycle_nonzero(output, bytes) ? 0 : -1;
}

static inline int
ker_nginx_cycle_parse_decimal(const char *text, uint64_t maximum,
    int require_nonzero, uint64_t *value)
{
    uint64_t parsed = 0;
    if (!text || !*text || !value) return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        unsigned digit = (unsigned)(*p - '0');
        if (parsed > maximum / 10 ||
            (parsed == maximum / 10 && digit > maximum % 10)) return -1;
        parsed = parsed * 10 + digit;
    }
    if (parsed > maximum || (require_nonzero && parsed == 0)) return -1;
    *value = parsed;
    return 0;
}

static inline int
ker_nginx_cycle_encode_header(uint8_t packet[KER_NGX_CYCLE_HEADER_BYTES],
    uint16_t type, uint32_t total_bytes, int32_t status,
    const uint8_t master_nonce[16], uint64_t master_start_ticks,
    uint64_t sequence, uint64_t cycle_id)
{
    if (!packet || !master_nonce || !ker_nginx_cycle_nonzero(master_nonce, 16) ||
        !master_start_ticks || !sequence || sequence == KER_NGX_CYCLE_MAX_SEQUENCE ||
        !cycle_id || status < 0 ||
        !((type == KER_NGX_CYCLE_WATCH_BOUND && total_bytes == KER_NGX_CYCLE_WATCH_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_DRAINED && total_bytes == KER_NGX_CYCLE_HEADER_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_READY && total_bytes == KER_NGX_CYCLE_WATCH_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_ERROR && total_bytes == KER_NGX_CYCLE_HEADER_BYTES && status > 0))) {
        errno = EINVAL;
        return -1;
    }
    memset(packet, 0, KER_NGX_CYCLE_HEADER_BYTES);
    ker_nginx_cycle_put32(packet, KER_NGX_CYCLE_MAGIC);
    ker_nginx_cycle_put16(packet + 4, KER_NGX_CYCLE_VERSION);
    ker_nginx_cycle_put16(packet + 6, type);
    ker_nginx_cycle_put32(packet + 8, total_bytes);
    ker_nginx_cycle_put32(packet + 12, (uint32_t)status);
    memcpy(packet + 16, master_nonce, 16);
    ker_nginx_cycle_put64(packet + 32, master_start_ticks);
    ker_nginx_cycle_put64(packet + 40, sequence);
    ker_nginx_cycle_put64(packet + 48, cycle_id);
    return 0;
}

static inline int
ker_nginx_cycle_decode(const uint8_t *packet, size_t packet_bytes,
    struct ker_nginx_cycle_header *header,
    struct ker_nginx_cycle_runtime *runtime)
{
    if (!packet || !header || packet_bytes < KER_NGX_CYCLE_HEADER_BYTES ||
        ker_nginx_cycle_get32(packet) != KER_NGX_CYCLE_MAGIC ||
        ker_nginx_cycle_get16(packet + 4) != KER_NGX_CYCLE_VERSION ||
        !ker_nginx_cycle_nonzero(packet + 16, 16) ||
        !ker_nginx_cycle_get64(packet + 32) ||
        !ker_nginx_cycle_get64(packet + 40) ||
        ker_nginx_cycle_get64(packet + 40) == KER_NGX_CYCLE_MAX_SEQUENCE ||
        !ker_nginx_cycle_get64(packet + 48) ||
        ker_nginx_cycle_get64(packet + 56) != 0) {
        errno = EPROTO;
        return -1;
    }
    uint16_t type = ker_nginx_cycle_get16(packet + 6);
    uint32_t total = ker_nginx_cycle_get32(packet + 8);
    uint32_t raw_status = ker_nginx_cycle_get32(packet + 12);
    if (raw_status > INT32_MAX) { errno = EPROTO; return -1; }
    int32_t status = (int32_t)raw_status;
    if (total != packet_bytes ||
        !((type == KER_NGX_CYCLE_WATCH_BOUND && total == KER_NGX_CYCLE_WATCH_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_DRAINED && total == KER_NGX_CYCLE_HEADER_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_READY && total == KER_NGX_CYCLE_WATCH_BYTES && status == 0) ||
          (type == KER_NGX_CYCLE_ERROR && total == KER_NGX_CYCLE_HEADER_BYTES && status > 0))) {
        errno = EPROTO;
        return -1;
    }
    if ((type == KER_NGX_CYCLE_WATCH_BOUND || type == KER_NGX_CYCLE_READY) &&
        (!runtime || !ker_nginx_cycle_nonzero(packet + 64, 16) ||
         !ker_nginx_cycle_get64(packet + 80) ||
         !ker_nginx_cycle_nonzero(packet + 88, 32))) {
        errno = EPROTO;
        return -1;
    }
    if (type == KER_NGX_CYCLE_DRAINED || type == KER_NGX_CYCLE_ERROR) {
        if (runtime || packet_bytes != KER_NGX_CYCLE_HEADER_BYTES) {
            errno = EPROTO;
            return -1;
        }
    } else {
        memcpy(runtime->broker_nonce, packet + 64, 16);
        runtime->broker_epoch = ker_nginx_cycle_get64(packet + 80);
        memcpy(runtime->worker_profile_sha256, packet + 88, 32);
    }
    header->type = type;
    header->total_bytes = total;
    header->status = status;
    memcpy(header->master_nonce, packet + 16, 16);
    header->master_start_ticks = ker_nginx_cycle_get64(packet + 32);
    header->sequence = ker_nginx_cycle_get64(packet + 40);
    header->cycle_id = ker_nginx_cycle_get64(packet + 48);
    return 0;
}

static inline int
ker_nginx_cycle_encode_runtime(uint8_t body[KER_NGX_CYCLE_RUNTIME_BYTES],
    const struct ker_nginx_cycle_runtime *runtime)
{
    if (!body || !runtime || !ker_nginx_cycle_nonzero(runtime->broker_nonce, 16) ||
        !runtime->broker_epoch ||
        !ker_nginx_cycle_nonzero(runtime->worker_profile_sha256, 32)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(body, runtime->broker_nonce, 16);
    ker_nginx_cycle_put64(body + 16, runtime->broker_epoch);
    memcpy(body + 24, runtime->worker_profile_sha256, 32);
    return 0;
}

typedef void (*ker_nginx_cycle_close_fd_fn)(int);

/* READY never accepts descriptor rights. Always close every installed fd,
 * including rights attached to a zero-length or truncated record. */
static inline int
ker_nginx_cycle_validate_ready_control(struct msghdr *message,
    struct ucred **credentials, ker_nginx_cycle_close_fd_fn close_fd)
{
    struct ucred *found = NULL;
    int bad = 0;
    if (!message || !credentials || !close_fd) return -1;
    if (message->msg_flags & (MSG_TRUNC | MSG_CTRUNC)) bad = 1;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(message); cmsg;
            cmsg = CMSG_NXTHDR(message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !found) {
            found = (struct ucred *)CMSG_DATA(cmsg);
        } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t payload_bytes;
            if (cmsg->cmsg_len < CMSG_LEN(0)) {
                bad = 1;
                continue;
            }
            payload_bytes = cmsg->cmsg_len - CMSG_LEN(0);
            if (payload_bytes % sizeof(int)) bad = 1;
            int *fds = (int *)CMSG_DATA(cmsg);
            for (size_t i = 0; i < payload_bytes / sizeof(int); ++i)
                close_fd(fds[i]);
            bad = 1;
        } else {
            bad = 1;
        }
    }
    if (!found) bad = 1;
    *credentials = found;
    return bad ? -1 : 0;
}

#endif
