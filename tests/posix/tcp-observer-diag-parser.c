#include "socket-broker-protocol.h"
#include "tcp-observer-diag-wire.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "diag parser:%d: %s\n", __LINE__, #test); return 1; } } while (0)

struct request_record {
    struct ker_nlmsghdr header;
    struct ker_inet_diag_req_v2 body;
} __attribute__((packed));

struct response_record {
    struct ker_nlmsghdr header;
    struct ker_inet_diag_msg body;
    struct ker_nlattr attribute;
    unsigned char payload;
    unsigned char padding[3];
} __attribute__((packed));

static void init_request(struct request_record *request)
{
    *request = (struct request_record){
        .header = {.length = sizeof(*request),
            .type = KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY,
            .flags = KER_TCP_OBSERVER_NLM_F_REQUEST, .sequence = 0x9354},
        .body = {.family = AF_INET, .protocol = KER_TCP_OBSERVER_PROTOCOL_TCP,
            .states = UINT32_MAX, .id = {.sport = 0x3412, .dport = 0x7856,
                .src = {0x01020304}, .dst = {0x05060708},
                .cookie = {0x87654321, 0x12345678}}}};
}

static void init_response(struct response_record *response,
    const struct request_record *request)
{
    *response = (struct response_record){
        .header = {.length = sizeof(*response),
            .type = KER_TCP_OBSERVER_SOCK_DIAG_BY_FAMILY,
            .sequence = request->header.sequence},
        .body = {.family = AF_INET, .state = 1,
            .id = request->body.id, .receive_queue = 4096, .send_queue = 8192},
        .attribute = {.length = sizeof(struct ker_nlattr) + 1, .type = 8},
        .payload = 0x42};
}

static int parse(const void *bytes, size_t length, const struct request_record *request,
    uint32_t sender, uint32_t local, struct ker_sb_tcp_observer_snapshot *snapshot)
{
    return ker_tcp_observer_parse_reply(bytes, length, sender, local, request,
        sizeof(*request), &request->body.id, snapshot);
}

int main(void)
{
    struct request_record request;
    struct response_record response;
    struct ker_sb_tcp_observer_snapshot snapshot = {0};
    init_request(&request);
    init_response(&response, &request);
    response.header.port_id = 44;
    CHECK(parse(&response, sizeof(response), &request, 0, 44, &snapshot) == 0);
    CHECK(snapshot.present == 1 && snapshot.cookie == UINT64_C(0x1234567887654321));
    CHECK(snapshot.state == 1 && snapshot.receive_queue == 4096 && snapshot.send_queue == 8192);
    CHECK(parse(&response, sizeof(response), &request, 5, 44, &snapshot) == -EPROTO);
    struct response_record malformed = response;
    malformed.header.sequence++;
    CHECK(parse(&malformed, sizeof(malformed), &request, 0, 44, &snapshot) == -EPROTO);
    malformed = response; malformed.header.port_id++;
    CHECK(parse(&malformed, sizeof(malformed), &request, 0, 44, &snapshot) == -EPROTO);
    malformed = response; malformed.header.length--;
    CHECK(parse(&malformed, sizeof(malformed), &request, 0, 44, &snapshot) == -EPROTO);
    malformed = response; malformed.attribute.length = 3;
    CHECK(parse(&malformed, sizeof(malformed), &request, 0, 44, &snapshot) == -EPROTO);
    malformed = response; malformed.header.flags = KER_TCP_OBSERVER_NLM_F_MULTI;
    CHECK(parse(&malformed, sizeof(malformed), &request, 0, 44, &snapshot) == -EPROTO);

    unsigned char error_reply[sizeof(struct ker_nlmsghdr) + sizeof(struct ker_nlmsgerr) +
        sizeof(request) - sizeof(struct ker_nlmsghdr) + sizeof(struct ker_nlattr) + 4] = {0};
    struct ker_nlmsghdr *error_header = (void *)error_reply;
    struct ker_nlmsgerr *error = (void *)(error_reply + sizeof(*error_header));
    *error_header = (struct ker_nlmsghdr){.length = sizeof(*error_header) + sizeof(*error) +
        sizeof(request) - sizeof(request.header), .type = KER_TCP_OBSERVER_NLMSG_ERROR,
        .sequence = request.header.sequence, .port_id = 44};
    error->request = request.header;
    memcpy(error_reply + sizeof(*error_header) + sizeof(*error),
        (const unsigned char *)&request + sizeof(request.header),
        sizeof(request) - sizeof(request.header));
    error->error = -ENOENT;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == 0);
    CHECK(snapshot.present == 0 && snapshot.cookie == UINT64_C(0x1234567887654321) &&
        !snapshot.state && !snapshot.receive_queue && !snapshot.send_queue);

    error_header->flags = KER_TCP_OBSERVER_NLM_F_CAPPED;
    error_header->length = sizeof(*error_header) + sizeof(*error);
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == 0);
    error_header->flags = 0;
    error_header->length = sizeof(*error_header) + sizeof(*error) +
        sizeof(request) - sizeof(request.header);
    error->error = -EACCES;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EACCES);
    error->error = -ENOENT;
    error_reply[sizeof(*error_header) + sizeof(*error) + 5] ^= 0xff;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EPROTO);
    error_reply[sizeof(*error_header) + sizeof(*error) + 5] ^= 0xff;
    error->error = -5000;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EPROTO);
    error->error = 0;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EPROTO);
    error->error = -ENOENT;
    error_header->flags = KER_TCP_OBSERVER_NLM_F_ACK_TLVS;
    error_header->length += sizeof(struct ker_nlattr) + 4;
    struct ker_nlattr *attribute = (void *)(error_reply + error_header->length - 8);
    *attribute = (struct ker_nlattr){.length = 3, .type = 1};
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EPROTO);
    attribute->length = sizeof(*attribute) + 1;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == 0);
    error_header->flags = 0;
    CHECK(parse(error_reply, error_header->length, &request, 0, 44, &snapshot) == -EPROTO);
    return 0;
}
