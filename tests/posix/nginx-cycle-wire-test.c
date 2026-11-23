#define _GNU_SOURCE
#include "nginx-cycle-wire.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static void
close_received_fd(int fd)
{
    assert(close(fd) == 0);
}

static void
test_empty_record_rights_are_closed(void)
{
    int pair[2], source, received_fd = -1;
    int passcred = 1;
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
    assert(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &passcred,
        sizeof(passcred)) == 0);
    source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(source >= 0);
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr outgoing = {.msg_control = control,
        .msg_controllen = sizeof(control)};
    struct cmsghdr *sent = CMSG_FIRSTHDR(&outgoing);
    assert(sent != NULL);
    sent->cmsg_level = SOL_SOCKET;
    sent->cmsg_type = SCM_RIGHTS;
    sent->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(sent), &source, sizeof(source));
    assert(sendmsg(pair[0], &outgoing, 0) == 0);

    char received_control[CMSG_SPACE(sizeof(struct ucred)) +
        CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr incoming = {.msg_control = received_control,
        .msg_controllen = sizeof(received_control)};
    assert(recvmsg(pair[1], &incoming, MSG_CMSG_CLOEXEC) == 0);
    struct cmsghdr *received = NULL;
    for (struct cmsghdr *item = CMSG_FIRSTHDR(&incoming); item;
            item = CMSG_NXTHDR(&incoming, item)) {
        if (item->cmsg_level == SOL_SOCKET && item->cmsg_type == SCM_RIGHTS) {
            received = item;
            break;
        }
    }
    assert(received != NULL && received->cmsg_len == CMSG_LEN(sizeof(int)));
    memcpy(&received_fd, CMSG_DATA(received), sizeof(received_fd));
    struct ucred *credentials = NULL;
    assert(ker_nginx_cycle_validate_ready_control(&incoming, &credentials,
        close_received_fd) == -1);
    assert(credentials != NULL && received_fd >= 0);
    errno = 0;
    assert(fcntl(received_fd, F_GETFD) == -1 && errno == EBADF);
    assert(close(source) == 0);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
}

int main(void)
{
    test_empty_record_rights_are_closed();
    uint8_t parsed_hex[4];
    uint64_t parsed_decimal = 0;
    assert(ker_nginx_cycle_parse_hex("0123abcd", parsed_hex, sizeof(parsed_hex)) == 0);
    assert(parsed_hex[0] == 0x01 && parsed_hex[1] == 0x23 &&
        parsed_hex[2] == 0xab && parsed_hex[3] == 0xcd);
    assert(ker_nginx_cycle_parse_hex("+123abcd", parsed_hex, sizeof(parsed_hex)) == -1);
    assert(ker_nginx_cycle_parse_hex("0123ABCD", parsed_hex, sizeof(parsed_hex)) == -1);
    assert(ker_nginx_cycle_parse_hex("00000000", parsed_hex, sizeof(parsed_hex)) == -1);
    assert(ker_nginx_cycle_parse_decimal("18446744073709551615", UINT64_MAX,
        1, &parsed_decimal) == 0 && parsed_decimal == UINT64_MAX);
    assert(ker_nginx_cycle_parse_decimal("-1", UINT64_MAX, 1, &parsed_decimal) == -1);
    assert(ker_nginx_cycle_parse_decimal("+1", UINT64_MAX, 1, &parsed_decimal) == -1);
    assert(ker_nginx_cycle_parse_decimal(" 1", UINT64_MAX, 1, &parsed_decimal) == -1);
    assert(ker_nginx_cycle_parse_decimal("18446744073709551616", UINT64_MAX,
        1, &parsed_decimal) == -1);
    assert(ker_nginx_cycle_parse_decimal("0", UINT64_MAX, 1, &parsed_decimal) == -1);

    const uint8_t master_nonce[16] = {1};
    const struct ker_nginx_cycle_runtime sent = {
        .broker_nonce = {2}, .broker_epoch = 0x0102030405060708ULL,
        .worker_profile_sha256 = {3}
    };
    uint8_t packet[KER_NGX_CYCLE_WATCH_BYTES] = {0};
    struct ker_nginx_cycle_header header = {0};
    struct ker_nginx_cycle_runtime received = {0};

    assert(ker_nginx_cycle_encode_header(packet, KER_NGX_CYCLE_WATCH_BOUND,
        KER_NGX_CYCLE_WATCH_BYTES, 0, master_nonce, 42, 1, 1) == 0);
    assert(packet[0] == 'K' && packet[1] == 'N' &&
        packet[2] == 'G' && packet[3] == 'C');
    assert(ker_nginx_cycle_encode_runtime(packet + KER_NGX_CYCLE_HEADER_BYTES,
        &sent) == 0);
    assert(ker_nginx_cycle_decode(packet, sizeof(packet), &header, &received) == 0);
    assert(header.type == KER_NGX_CYCLE_WATCH_BOUND &&
        header.total_bytes == sizeof(packet) && header.status == 0 &&
        header.master_start_ticks == 42 && header.sequence == 1 &&
        header.cycle_id == 1);
    assert(memcmp(header.master_nonce, master_nonce, sizeof(master_nonce)) == 0);
    assert(memcmp(received.broker_nonce, sent.broker_nonce, 16) == 0 &&
        received.broker_epoch == sent.broker_epoch &&
        memcmp(received.worker_profile_sha256, sent.worker_profile_sha256, 32) == 0);

    assert(ker_nginx_cycle_decode(packet, sizeof(packet) - 1, &header, &received) == -1);
    assert(errno == EPROTO);
    packet[56] = 1;
    assert(ker_nginx_cycle_decode(packet, sizeof(packet), &header, &received) == -1);
    assert(errno == EPROTO);
    packet[56] = 0;
    packet[64] = 0;
    assert(ker_nginx_cycle_decode(packet, sizeof(packet), &header, &received) == -1);
    assert(errno == EPROTO);
    packet[64] = 2;

    memset(packet, 0, KER_NGX_CYCLE_HEADER_BYTES);
    assert(ker_nginx_cycle_encode_header(packet, KER_NGX_CYCLE_DRAINED,
        KER_NGX_CYCLE_HEADER_BYTES, 0, master_nonce, 42, 2, 1) == 0);
    assert(ker_nginx_cycle_decode(packet, KER_NGX_CYCLE_HEADER_BYTES,
        &header, NULL) == 0);
    assert(header.type == KER_NGX_CYCLE_DRAINED && header.sequence == 2);
    assert(ker_nginx_cycle_decode(packet, KER_NGX_CYCLE_HEADER_BYTES,
        &header, &received) == -1);
    assert(errno == EPROTO);

    assert(ker_nginx_cycle_encode_header(packet, KER_NGX_CYCLE_ERROR,
        KER_NGX_CYCLE_HEADER_BYTES, 0, master_nonce, 42, 3, 1) == -1);
    assert(errno == EINVAL);
    assert(ker_nginx_cycle_encode_header(packet, KER_NGX_CYCLE_ERROR,
        KER_NGX_CYCLE_HEADER_BYTES, EIO, master_nonce, 42, 3, 1) == 0);
    assert(ker_nginx_cycle_decode(packet, KER_NGX_CYCLE_HEADER_BYTES,
        &header, NULL) == 0 && header.status == EIO);
    return 0;
}
