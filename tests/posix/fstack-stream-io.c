/* Ker-specific independent-peer extension of pinned F-Stack message/vector
 * bridge scenarios. TCP boundaries are never treated as message boundaries. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
#define TOTAL (256U * 1024U + 13U)
#define CHUNK 8192U
#define BATCH 3U
enum api { VECTOR, MESSAGE, BATCHED };
static unsigned int send_partial, send_retry, receive_short, receive_retry;
static unsigned char value(size_t offset, unsigned int seed)
{
    return (unsigned char)((offset * 131U + (offset >> 7) + seed) & 255U);
}
static void wait_for(int fd, short events)
{
    struct pollfd p = {fd, events, 0};
    int result;
    do { result = poll(&p, 1, 10000); } while (result < 0 && errno == EINTR);
    CHECK(result == 1 && !(p.revents & POLLNVAL));
    CHECK(p.revents & (events | POLLERR | POLLHUP));
}
static void configure(int fd)
{
    int flags = fcntl(fd, F_GETFL), size = 4096;
    CHECK(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
}
static size_t minimum(size_t a, size_t b) {return a < b ? a : b;}
static void transmit(int fd, enum api api, unsigned int seed)
{
    unsigned char *bytes = malloc(TOTAL);
    CHECK(bytes != NULL);
    for (size_t i = 0; i < TOTAL; ++i) bytes[i] = value(i, seed);
    size_t offset = 0;
    while (offset < TOTAL) {
        ssize_t count;
        size_t offered;
        if (api == BATCHED) {
            struct mmsghdr messages[BATCH] = {0};
            struct iovec vectors[BATCH][2];
            size_t prepared = 0;
            unsigned int n = 0;
            while (n < BATCH && offset + prepared < TOTAL) {
                size_t length = minimum(CHUNK, TOTAL - offset - prepared), split = length / 3;
                vectors[n][0] = (struct iovec){bytes + offset + prepared, split};
                vectors[n][1] = (struct iovec){bytes + offset + prepared + split, length - split};
                messages[n].msg_hdr.msg_iov = vectors[n]; messages[n].msg_hdr.msg_iovlen = 2;
                prepared += length; ++n;
            }
            offered = prepared;
            int sent = sendmmsg(fd, messages, n, MSG_NOSIGNAL);
            count = sent < 0 ? -1 : 0;
            if (sent >= 0) {
                CHECK(sent > 0 && (unsigned int)sent <= n);
                for (int i = 0; i < sent; ++i) {
                    size_t maximum = vectors[i][0].iov_len + vectors[i][1].iov_len;
                    CHECK(messages[i].msg_len > 0 && messages[i].msg_len <= maximum);
                    count += messages[i].msg_len;
                    /* Linux stops the batch after a partial stream message. */
                    if (messages[i].msg_len < maximum) CHECK(i + 1 == sent);
                }
            }
        } else {
            size_t length = minimum(CHUNK, TOTAL - offset), split = length / 3;
            offered = length;
            struct iovec vectors[] = {{bytes + offset, split}, {NULL, 0},
                {bytes + offset + split, length - split}};
            struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
            count = api == VECTOR ? writev(fd, vectors, 3) : sendmsg(fd, &message, MSG_NOSIGNAL);
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {++send_retry; wait_for(fd, POLLOUT); continue;}
        CHECK(count > 0 && (size_t)count <= TOTAL - offset);
        if ((size_t)count < offered) ++send_partial;
        offset += (size_t)count;
    }
    free(bytes);
    CHECK(shutdown(fd, SHUT_WR) == 0);
}
static void verify(const unsigned char *bytes, size_t length, size_t *offset, unsigned int seed)
{
    CHECK(length > 0 && length <= TOTAL - *offset);
    for (size_t i = 0; i < length; ++i) CHECK(bytes[i] == value(*offset + i, seed));
    *offset += length;
}
static void receive_stream(int fd, enum api api, unsigned int seed)
{
    size_t offset = 0;
    while (offset < TOTAL) {
        ssize_t count;
        unsigned char bytes[CHUNK];
        if (api == BATCHED) {
            unsigned char batch[BATCH][CHUNK];
            struct iovec vectors[BATCH];
            struct mmsghdr messages[BATCH] = {0};
            for (unsigned int i = 0; i < BATCH; ++i) {
                vectors[i] = (struct iovec){batch[i], sizeof(batch[i])};
                messages[i].msg_hdr.msg_iov = &vectors[i]; messages[i].msg_hdr.msg_iovlen = 1;
            }
            int received = recvmmsg(fd, messages, BATCH, MSG_DONTWAIT, NULL);
            count = received < 0 ? -1 : 0;
            if (received >= 0) {
                CHECK(received > 0 && (unsigned int)received <= BATCH);
                for (int i = 0; i < received; ++i) {
                    CHECK(messages[i].msg_len <= CHUNK && !(messages[i].msg_hdr.msg_flags & MSG_TRUNC));
                    if (!messages[i].msg_len) {CHECK(offset == TOTAL); continue;}
                    if (TOTAL - offset >= CHUNK && messages[i].msg_len < CHUNK) ++receive_short;
                    verify(batch[i], messages[i].msg_len, &offset, seed);
                    count += messages[i].msg_len;
                }
            }
        } else {
            struct iovec vectors[] = {{bytes, 1031}, {NULL, 0}, {bytes + 1031, sizeof(bytes) - 1031}};
            struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
            count = api == VECTOR ? readv(fd, vectors, 3) : recvmsg(fd, &message, 0);
            if (count > 0) {
                CHECK((size_t)count <= sizeof(bytes) && !(message.msg_flags & MSG_TRUNC));
                if (TOTAL - offset >= CHUNK && (size_t)count < CHUNK) ++receive_short;
                verify(bytes, (size_t)count, &offset, seed);
            }
        }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {++receive_retry; wait_for(fd, POLLIN); continue;}
        CHECK(count > 0);
    }
    unsigned char byte;
    for (;;) {
        ssize_t count = recv(fd, &byte, 1, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {++receive_retry; wait_for(fd, POLLIN); continue;}
        CHECK(count == 0); break;
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 5);
    int server = strcmp(argv[1], "server") == 0;
    CHECK(server || strcmp(argv[1], "client") == 0);
    enum api api;
    if (strcmp(argv[4], "vector") == 0) api = VECTOR;
    else if (strcmp(argv[4], "message") == 0) api = MESSAGE;
    else {CHECK(strcmp(argv[4], "batch") == 0); api = BATCHED;}
    char *end;
    long port = strtol(argv[3], &end, 10);
    CHECK(!*end && port > 0 && port <= 65535);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    if (server) {
        int reuse = 1;
        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 4) == 0);
        printf("READY %ld\n", port); fflush(stdout);
        int child = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        CHECK(child >= 0 && close(fd) == 0); fd = child;
    } else CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
    configure(fd);
    if (server) {receive_stream(fd, api, 17); transmit(fd, api, 93);}
    else {transmit(fd, api, 17); receive_stream(fd, api, 93);}
    CHECK(close(fd) == 0);
    printf("PASS: F-Stack %s stream I/O, %u bytes each direction, nonblocking and EOF; "
        "send_partial=%u send_eagain=%u recv_short=%u recv_eagain=%u\n",
        argv[4], TOTAL, send_partial, send_retry, receive_short, receive_retry);
    return 0;
}
