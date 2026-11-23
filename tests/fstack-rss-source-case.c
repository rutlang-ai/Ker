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
#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#include STRINGIFY(SOURCE_INCLUDE)
int main(void)
{
    for (unsigned i = 0; i < 5; ++i) {
        example_rss_reset();
        SOURCE_FUNCTION(NULL);
        example_rss_reset();
    }
    return 0;
}
