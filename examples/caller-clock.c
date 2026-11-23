#include "caller-clock.h"
/* DPDK's unit constant; this pure function does not require EAL initialization. */
#define US_PER_S UINT64_C(1000000)
#define ff_hardclock_interval_tsc example_caller_interval_ticks
#include "interval.inc"
