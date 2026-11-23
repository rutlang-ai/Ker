#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "check.h"
#include "rss-table-policy.h"
#include "rss-table-internal.h"
#include <ker/packet-dispatcher.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_ring.h>
#define assert_int_equal(a, b) CHECK((a) == (b))
#include "fstack-rss-table-source.inc"

static void verify_candidate_window(int family, uint16_t eligible_port)
{
    struct ff_rss_check_cfg rules = {.enable = 1, .nb_rss_tbl = 1};
    struct ff_rss_tbl_cfg *rule = &rules.rss_tbl_cfgs[0];
    rule->family = family;
    rule->sport = htons(9000);
    uint8_t packet[48] = {0};
    uint16_t length;
    if (family == AF_INET) {
        CHECK(inet_pton(family, "192.0.2.1", &rule->saddr) == 1);
        CHECK(inet_pton(family, "198.51.100.2", &rule->daddr) == 1);
        packet[0] = 0x45; packet[9] = 17;
        memcpy(packet + 12, &rule->saddr, 4);
        memcpy(packet + 16, &rule->daddr, 4);
        length = 28;
    } else {
        CHECK(inet_pton(family, "2001:db8::1", rule->saddr6) == 1);
        CHECK(inet_pton(family, "2001:db8::2", rule->daddr6) == 1);
        packet[0] = 0x60; packet[6] = 17;
        memcpy(packet + 8, rule->saddr6, 16);
        memcpy(packet + 24, rule->daddr6, 16);
        length = 48;
    }
    uint16_t destination = htons(eligible_port);
    memcpy(packet + length - 8, &rule->sport, 2);
    memcpy(packet + length - 6, &destination, 2);
    CHECK(example_rss_configure(&rules, 4, 1, 128, eligible_port, eligible_port) == 0);
    CHECK(example_rss_dispatch(packet, &length, 1, 4) == 1);
    CHECK(example_rss_configure(&rules, 4, 1, 128, 10000, 10000) == -EINVAL);
    CHECK(example_rss_dispatch(packet, &length, 1, 4) < 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "candidate-window")) {
        verify_candidate_window(AF_INET, 10002);
        verify_candidate_window(AF_INET6, 10001);
        return 0;
    }
    CHECK(argc == 1);
    test_ff_rss_tbl_set_portrange_no_cfg(NULL);
    example_rss_reset();
    return 0;
}
