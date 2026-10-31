#include <stdio.h>
#include "caller-clock.h"
/* Test-only mutation: lose the original ceiling term, retaining all inputs. */
uint64_t __wrap_example_caller_interval_ticks(uint64_t clock_hz, unsigned polls_per_second)
{
    if (!polls_per_second || polls_per_second > 1000000) return 0;
    fputs("CALLER_CLOCK_ROUND_DOWN\n", stderr);
    return (clock_hz / 1000000) * (1000000 / polls_per_second);
}
