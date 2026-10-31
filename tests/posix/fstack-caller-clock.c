#define _GNU_SOURCE
#include "check.h"
#include "caller-clock.h"
#include "host-readiness-native.h"
#define US_PER_S UINT64_C(1000000)
#define ff_hardclock_interval_tsc example_caller_interval_ticks
#define assert_int_equal(a, b) CHECK((a) == (b))
#include "fstack-caller-clock-source.inc"
int main(void)
{
    example_require_native();
    for (unsigned i = 0; i < 5; ++i)
        test_ut_nr_17_hardclock_interval(NULL);
    example_finish_native();
    puts("CLOCK_SOURCE_CASE test_ut_nr_17_hardclock_interval");
    return 0;
}
