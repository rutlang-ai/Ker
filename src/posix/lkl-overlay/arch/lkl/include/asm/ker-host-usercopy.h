/* Ker's Linux/x86_64 host memory adapter. No libc, kernel state or signals. */
#ifndef KER_HOST_USERCOPY_H
#define KER_HOST_USERCOPY_H
#if !defined(__linux__) || !defined(__x86_64__)
#error "Ker native usercopy requires the Linux x86_64 host syscall ABI"
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long) == 8, "host usercopy ABI");
struct ker_host_iovec { void *base; unsigned long length; };
static inline long ker_host_pid(void)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "0"(39L) : "rcx", "r11", "cc", "memory");
    return result;
}
static inline long ker_host_vm_transfer(void *to, const void *from, unsigned long length, int write)
{
    if (!length) return 0;
    if (length > (~0UL >> 1) || (unsigned long)to > ~0UL - (length - 1) ||
        (unsigned long)from > ~0UL - (length - 1)) return -14;
    struct ker_host_iovec local = {write ? (void *)from : to, length};
    struct ker_host_iovec remote = {write ? to : (void *)from, length};
    long pid = ker_host_pid();
    if (pid <= 0) return pid < 0 ? pid : -3;
    register long fourth __asm__("r10") = (long)&remote;
    register long fifth __asm__("r8") = 1;
    register long sixth __asm__("r9") = 0;
    long copied;
    /* process_vm_{readv,writev} use the host MM to validate user addresses,
     * including protection and page faults, without installing signal handlers. */
    __asm__ volatile("syscall" : "=a"(copied)
        : "0"(write ? 311L : 310L), "D"(pid), "S"(&local), "d"(1L),
          "r"(fourth), "r"(fifth), "r"(sixth)
        : "rcx", "r11", "cc", "memory");
    return copied;
}
static inline unsigned long ker_host_usercopy(void *to, const void *from, unsigned long length, int write)
{
    long copied = ker_host_vm_transfer(to, from, length, write);
    return copied < 0 || (unsigned long)copied > length ? length : length - (unsigned long)copied;
}
static inline unsigned long ker_host_clear_user(void *to, unsigned long length)
{
    static const unsigned char zero[4096];
    if (length && (unsigned long)to > ~0UL - (length - 1)) return length;
    unsigned long done = 0;
    while (done < length) {
        unsigned long count = length - done;
        if (count > sizeof(zero)) count = sizeof(zero);
        unsigned long left = ker_host_usercopy((void *)((unsigned long)to + done), zero, count, 1);
        done += count - left;
        if (left) break;
    }
    return length - done;
}
#endif
