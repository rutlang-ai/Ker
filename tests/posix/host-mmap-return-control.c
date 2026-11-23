#define _DEFAULT_SOURCE
#include <sys/mman.h>
#include "host-mapping.h"
/* Negative control: real Ker mmap error return without the caller's exit policy. */
void *__wrap_example_host_mmap(void *address, uint64_t length, int protection,
    int flags, int fd, uint64_t offset)
{
    int prot = ((protection & ff_PROT_READ) ? PROT_READ : 0) |
               ((protection & ff_PROT_WRITE) ? PROT_WRITE : 0);
    int host_flags = ((flags & ff_MAP_SHARED) ? MAP_SHARED : 0) |
                     ((flags & ff_MAP_PRIVATE) ? MAP_PRIVATE : 0) |
                     ((flags & ff_MAP_ANON) ? MAP_ANONYMOUS : 0);
    return mmap(address, length, prot, host_flags, fd, offset);
}
