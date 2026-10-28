/* Exact host mmap scenarios through the active Ker POSIX owner adapter. */
#define _GNU_SOURCE
#include <ker/posix.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s errno=%d\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static void (*native_stop)(void);
static int stop(void *unused) { (void)unused; native_stop(); return 0; }
static void reclaimed(void *p, size_t length)
{
    unsigned char resident[2];
    CHECK(mincore(p, length, resident) == -1 && errno == ENOMEM);
}
static void shared(void)
{
    size_t length = 4096; /* Literal upstream profile. */
    unsigned char *p = mmap(NULL, length, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED);
    for (size_t i = 0; i < length; i++) CHECK(p[i] == 0);
    p[0] = 0x53; p[length-1] = 0xa9;
    CHECK(p[0] == 0x53 && p[length-1] == 0xa9);
    CHECK(!munmap(p, length)); reclaimed(p, length);
    /* Anonymous fd is ignored even when its integer names a native socket.
     * The live socket must not be mistaken for a host mapping descriptor. */
    int native = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(native >= 0);
    p = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, native, 0);
    CHECK(p != MAP_FAILED && !p[0]); p[0] = 0x35;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(!bind(native, (void *)&address, sizeof(address)));
    CHECK(!munmap(p, length)); reclaimed(p, length); CHECK(!close(native));
    puts("HOST_SOURCE_CASE test_ff_mmap_map_shared_anon");
}
static void file_backed(void)
{
    char path[] = "/tmp/ker-host-file-map-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0);
    CHECK(!unlink(path) && !ftruncate(fd, 8192));
    unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED);
    for (size_t i = 0; i < 4096; i++) CHECK(!p[i]);
    p[0] = 0x91; p[4095] = 0x19;
    unsigned char byte = 0xff;
    CHECK(pread(fd, &byte, 1, 0) == 1 && !byte); /* Real private COW. */
    CHECK(pread(fd, &byte, 1, 4095) == 1 && !byte);
    CHECK(!munmap(p, 4096)); reclaimed(p, 4096);
    CHECK(pwrite(fd, "offset", 6, 4096) == 6);
    p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 4096);
    CHECK(p != MAP_FAILED && !memcmp(p, "offset", 6));
    CHECK(!close(fd) && !memcmp(p, "offset", 6));
    CHECK(!munmap(p, 4096)); reclaimed(p, 4096);
    /* A native descriptor must never fall through to the host placeholder. */
    int native = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0); CHECK(native >= 0);
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, native, 1) == MAP_FAILED && errno == EINVAL);
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, native, 0) == MAP_FAILED && errno == EINVAL);
    CHECK(!close(native));
    puts("HOST_SOURCE_CASE test_ff_mmap_file_backed_no_anon");
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    uint64_t (*capabilities)(void) = dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(capabilities && release && (capabilities() & KER_CAP_LINUX_STACK));
    CHECK(release() && !strncmp(release(), "6.12.113", 8));
    Dl_info mapping, runtime;
    CHECK(dladdr(dlsym(RTLD_DEFAULT, "mmap"), &mapping));
    CHECK(dladdr((void *)capabilities, &runtime) && mapping.dli_fbase == runtime.dli_fbase);
    /* Positive results cannot come from an unguarded host networking process. */
    CHECK(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
    if (!strcmp(argv[1], "shared")) shared();
    else if (!strcmp(argv[1], "file")) file_backed();
    else CHECK(0);
    int (*native_run)(ker_posix_loop_func, void *) = dlsym(RTLD_DEFAULT, "ker_posix_run");
    native_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    CHECK(native_run && native_stop && !native_run(stop, NULL));
    CHECK(!capabilities() && !release());
    return 0;
}
