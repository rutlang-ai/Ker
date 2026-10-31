#ifndef EXAMPLE_HOST_MAPPING_H
#define EXAMPLE_HOST_MAPPING_H
#include <stdint.h>
#include "memory-flags.inc"
/* The retained fatal-error policy belongs to this caller, not Ker's mmap ABI. */
void *example_host_mmap(void *address, uint64_t length, int protection,
    int flags, int fd, uint64_t offset);
int example_host_munmap(void *address, uint64_t length);
#endif
