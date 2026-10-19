// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-memory.h"
#include <sys/mman.h>
#include <lkl_host.h>

/* The pinned LKL POSIX callback unmaps the requested address on failure.
 * A collision must preserve that existing mapping. Keep this correction in
 * Ker's host adapter so the imported LKL source remains unchanged.
 * See tools/lkl/lib/posix-host.c::lkl_mmap in the pinned source. */
static void *map_exact(void *address, unsigned long size, enum lkl_prot protection)
{
    int prot = PROT_NONE;
    if (protection & LKL_PROT_READ) prot |= PROT_READ;
    if (protection & LKL_PROT_WRITE) prot |= PROT_WRITE;
    if (protection & LKL_PROT_EXEC) prot |= PROT_EXEC;
    void *result = mmap(address, size, prot,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE, -1, 0);
    if (result == MAP_FAILED) return NULL;
    if (result != address) {
        /* Older hosts may ignore MAP_FIXED_NOREPLACE. Release only the
         * mapping just returned, and report the exact-address failure. */
        munmap(result, size);
        return NULL;
    }
    return result;
}
void ker_native_host_memory_init(struct lkl_host_operations *ops)
{
    ops->mmap = map_exact;
}
