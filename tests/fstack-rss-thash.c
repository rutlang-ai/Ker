/* The pinned cases consume real DPDK thash directly; no Ker port-selection
 * implementation or device queue dispatch is introduced by this fixture. */
#define _GNU_SOURCE
#include "eal.h"
#include <arpa/inet.h>
#include <rte_random.h>
#include <rte_thash.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned initialized;
static int equiv_eal_init_once(void)
{
    if (!initialized) {
        ker_test_eal_init();
        CHECK(rte_eal_process_type() == RTE_PROC_PRIMARY);
        initialized = 1;
    }
    return 1;
}

/* Any EAL failure exits through CHECK; the retained source skip branches may
 * never silently turn a missing dependency into an accepted source case. */
#define skip() CHECK(0)
#define assert_true(value) CHECK(value)
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_int_equal(left, right) CHECK((left) == (right))
#include "fstack-rss-thash-source.inc"

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "ipv4")) test_ff_rss_thash_equivalence_hitrate(NULL);
    else {
        CHECK(!strcmp(argv[1], "ipv6"));
        test_ff_rss_thash6_equivalence_hitrate(NULL);
    }
    CHECK(initialized == 1);
    CHECK(!rte_thash_find_existing("ff_equiv_128"));
    CHECK(!rte_thash_find_existing("ff_equiv_512"));
    CHECK(!rte_thash_find_existing("ff_equiv6_128"));
    CHECK(!rte_thash_find_existing("ff_equiv6_512"));
    CHECK(!rte_eal_cleanup());
    printf("PASS: original %s thash assertions, two real contexts freed, EAL cleaned\n", argv[1]);
    return 0;
}
