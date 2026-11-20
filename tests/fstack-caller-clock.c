#include "check.h"
#include "caller-clock.h"
#define US_PER_S UINT64_C(1000000)
#define ff_hardclock_interval_tsc example_caller_interval_ticks
#define assert_int_equal(left, right) CHECK((left) == (right))
#include "fstack-caller-clock-source.inc"

int main(void)
{
    test_ut_nr_17_hardclock_interval(NULL);
    return 0;
}
