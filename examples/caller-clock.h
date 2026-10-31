#ifndef EXAMPLE_CALLER_CLOCK_H
#define EXAMPLE_CALLER_CLOCK_H
#include <stdint.h>
/* Clock ticks per poll, using the retained legacy microsecond quantization. */
uint64_t example_caller_interval_ticks(uint64_t clock_hz, unsigned polls_per_second);
#endif
