#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "check.h"
#include "rss-table-policy.h"
#include "rss-table-internal.h"
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_int_not_equal(a, b) CHECK((a) != (b))
#define assert_non_null(p) CHECK((p) != NULL)
#define assert_null(p) CHECK((p) == NULL)
#define assert_true(p) CHECK(p)
#define assert_ptr_equal(a, b) CHECK((a) == (b))
#include "fstack-rss-source-helpers.inc"
#include "fstack-rss-table-source.inc"
#include "fstack-rss-source/test_ff_rss_tbl_set_portrange_disabled.inc"
#include "fstack-rss-source/test_ff_rss_tbl_set_portrange_inverted_range.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_no_cfg.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_disabled.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_smoke.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_hit.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_rotation.inc"
#include "fstack-rss-source/test_ff_rss_tbl_get_portrange_miss.inc"
#include "fstack-rss-source/test_ff_rss_check6_landing.inc"
#include "fstack-rss-source/test_ff_rss_check6_single_queue.inc"
#include "fstack-rss-source/test_ff_rss_tbl6_set_get.inc"

#define TABLE_CASE(function) {#function, function}
static const struct {
    const char *name;
    void (*test)(void **state);
} cases[] = {
    TABLE_CASE(test_ff_rss_tbl_set_portrange_no_cfg),
    TABLE_CASE(test_ff_rss_tbl_set_portrange_disabled),
    TABLE_CASE(test_ff_rss_tbl_set_portrange_inverted_range),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_no_cfg),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_disabled),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_smoke),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_hit),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_rotation),
    TABLE_CASE(test_ff_rss_tbl_get_portrange_miss),
    TABLE_CASE(test_ff_rss_check6_landing),
    TABLE_CASE(test_ff_rss_check6_single_queue),
    TABLE_CASE(test_ff_rss_tbl6_set_get),
};

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        if (strcmp(argv[1], cases[i].name) != 0)
            continue;
        for (unsigned iteration = 0; iteration < 5; ++iteration) {
            cases[i].test(NULL);
            example_rss_reset();
        }
        return 0;
    }
    fprintf(stderr, "Unknown RSS table case: %s\n", argv[1]);
    return EXIT_FAILURE;
}
