#define _GNU_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include "check.h"
#include "eal.h"
#include "rss-table-policy.h"
#include "rss-table-internal.h"
#include <ker/packet-dispatcher.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_ring.h>
#define assert_int_equal(a, b) CHECK((a) == (b))
#include "fstack-rss-table-source.inc"

int main(void)
{
    test_ff_rss_tbl_set_portrange_no_cfg(NULL);
    example_rss_reset();
    return 0;
}
