#define _GNU_SOURCE
#include <asm/ker-host-usercopy.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do {if (!(x)) {fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1);}} while (0)
_Static_assert(sizeof(struct ker_host_iovec) == 16 && offsetof(struct ker_host_iovec, length) == 8, "Linux x86_64 iovec layout");
int ker_native_host_usercopy_probe(void);
static void denied_probe(int operation, int error)
{
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct sock_filter code[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, operation, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (unsigned)error),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
        struct sock_fprog program = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
        CHECK(ker_native_host_usercopy_probe() == -error);
        _exit(0);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static double elapsed(struct timespec a, struct timespec b)
{ return b.tv_sec - a.tv_sec + (b.tv_nsec - a.tv_nsec) * 1e-9; }
static void benchmark(void)
{
    unsigned char *a = malloc(65536), *b = malloc(65536); CHECK(a && b); memset(a, 0x75, 65536);
    volatile unsigned accumulator = 0;
    for (size_t length = 64; length <= 65536; length *= 1024) {
        enum {iterations = 10000}; struct timespec start, end;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
        for (unsigned i = 0; i < iterations; ++i) {memcpy(b, a, length); accumulator += b[i % length];}
        CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0); double direct = elapsed(start, end);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
        for (unsigned i = 0; i < iterations; ++i) {CHECK(!ker_host_usercopy(b, a, length, 0)); accumulator += b[i % length];}
        CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0); double adapted = elapsed(start, end);
        printf("usercopy benchmark: bytes=%zu memcpy_MiB_s=%.1f fault_safe_MiB_s=%.1f fault_safe_ns=%.0f\n",
            length, length * (double)iterations / direct / 1048576, length * (double)iterations / adapted / 1048576, adapted * 1e9 / iterations);
    }
    CHECK(accumulator); free(b); free(a);
}
int main(int argc, char **argv)
{
    CHECK(ker_native_host_usercopy_probe() == 0);
    /* These children exercise only the standalone host adapter, never LKL. */
    denied_probe(SYS_process_vm_readv, EPERM); denied_probe(SYS_process_vm_writev, EPERM);
    denied_probe(SYS_process_vm_readv, ENOSYS); denied_probe(SYS_process_vm_writev, ENOSYS);
    long page = sysconf(_SC_PAGESIZE); CHECK(page > 256);
    unsigned char *source = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *target = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(source != MAP_FAILED && target != MAP_FAILED); memset(source, 0x65, (size_t)page * 2); memset(target, 0xa5, (size_t)page * 2);
    errno = EDOM;
    CHECK(ker_host_usercopy(target, source, (unsigned long)page, 0) == 0 && target[page - 1] == 0x65);
    CHECK(ker_host_usercopy(target, source, (unsigned long)page, 1) == 0 && errno == EDOM);
    CHECK(ker_host_usercopy(NULL, NULL, 0, 0) == 0 && ker_host_clear_user(NULL, 0) == 0);
    CHECK(ker_host_usercopy(target, NULL, 1, 0) == 1 && ker_host_usercopy(NULL, source, 1, 1) == 1);
    CHECK(ker_host_usercopy(target, (void *)(ULONG_MAX - 1), 4, 0) == 4);
    CHECK(ker_host_usercopy((void *)(ULONG_MAX - 1), source, 4, 1) == 4);
    CHECK(ker_host_usercopy(target, source, ULONG_MAX, 0) == ULONG_MAX);
    CHECK(mprotect(source + page, (size_t)page, PROT_NONE) == 0);
    unsigned char bytes[14]; memset(bytes, 0xa5, sizeof(bytes));
    CHECK(ker_host_usercopy(bytes, source + page - 7, sizeof(bytes), 0) == 7);
    for (unsigned i = 0; i < sizeof(bytes); ++i) CHECK(bytes[i] == (i < 7 ? 0x65 : 0xa5));
    CHECK(ker_host_usercopy(bytes, source + page, sizeof(bytes), 0) == sizeof(bytes));
    CHECK(mprotect(target + page, (size_t)page, PROT_NONE) == 0);
    CHECK(ker_host_usercopy(target + page - 7, source, 14, 1) == 7);
    CHECK(ker_host_clear_user(target + page - 5, 12) == 7);
    for (int i = 0; i < 5; ++i) CHECK(target[page - 5 + i] == 0);
    CHECK(mprotect(target + page, (size_t)page, PROT_READ | PROT_WRITE) == 0);
    CHECK(target[page] == 0xa5);
    CHECK(mprotect(target, (size_t)page, PROT_READ) == 0);
    CHECK(ker_host_usercopy(target, source, 1, 1) == 1);
    CHECK(munmap(source, (size_t)page * 2) == 0);
    CHECK(ker_host_usercopy(bytes, source, 1, 0) == 1);
    CHECK(munmap(target, (size_t)page * 2) == 0 && errno == EDOM);
    if (argc == 2 && !strcmp(argv[1], "--benchmark")) benchmark();
    puts("PASS: host usercopy protected/unmapped/partial/overflow/zero-length boundaries"); return 0;
}
