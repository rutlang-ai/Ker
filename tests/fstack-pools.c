/* Private source preconditions against the actual production TU. */
#include "../src/compat/pools.c"
#include "check.h"
#define assert_int_equal(left, right) CHECK((left) == (right))
#define assert_string_equal(left, right) CHECK(!strcmp((left), (right)))
#define assert_ptr_equal(left, right) CHECK((left) == (right))
#define assert_null(value) CHECK((value) == NULL)
#define assert_true(value) CHECK(value)
#include "fstack-pool-source.inc"
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "generation")) test_ut_nr_18_gen_pool_config(NULL);
    else if (argc == 2 && !strcmp(argv[1], "cache")) test_ut_nr_21_shared_pool_cache_size(NULL);
    else { CHECK(argc == 1); test_ut_nr_18_gen_pool_config(NULL); test_ut_nr_21_shared_pool_cache_size(NULL); }
    puts("PASS: complete original generation-pool and cache-policy assertions");
    return 0;
}
