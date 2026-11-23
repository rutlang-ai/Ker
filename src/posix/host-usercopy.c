#define _GNU_SOURCE
#include "lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
/* Check both successful copies and denied accesses before booting LKL. Hosts
 * without process_vm permissions cannot safely provide this memory adapter. */
int ker_native_host_usercopy_probe(void)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return -EOPNOTSUPP;
    unsigned char *memory = (void *)syscall(SYS_mmap, NULL, (size_t)page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return -errno;
    int result = -EOPNOTSUPP;
    unsigned char input = 0x79, output = 0;
    long transferred = ker_host_vm_transfer(memory, &input, 1, 1);
    if (transferred != 1) {result = transferred < 0 ? (int)transferred : -EIO; goto done;}
    transferred = ker_host_vm_transfer(&output, memory, 1, 0);
    if (transferred != 1) {result = transferred < 0 ? (int)transferred : -EIO; goto done;}
    if (output != input) {result = -EIO; goto done;}
    if (syscall(SYS_mprotect, memory + page, (size_t)page, PROT_NONE)) {result = -errno; goto done;}
    if (ker_host_usercopy(&output, memory + page, 1, 0) != 1 ||
        ker_host_usercopy(memory + page, &input, 1, 1) != 1) goto done;
    result = 0;
done:
    (void)syscall(SYS_munmap, memory, (size_t)page * 2);
    return result;
}
