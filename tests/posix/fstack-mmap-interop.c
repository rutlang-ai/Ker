/* POSIX process mappings used by an application of the original Linux stack. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); exit(1); } } while (0)
static unsigned char pattern(size_t index) { return (unsigned char)(index * 37 + 11); }
static void mapping_mode(void *address, char mode)
{
    FILE *maps = fopen("/proc/self/maps", "r"); CHECK(maps);
    char line[1024], permissions[5];
    unsigned long start, end;
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) != 3) continue;
        if ((unsigned long)address >= start && (unsigned long)address < end) {
            CHECK(permissions[0] == 'r' && permissions[1] == 'w' && permissions[3] == mode);
            found = 1; break;
        }
    }
    CHECK(fclose(maps) == 0 && found);
}
static void release_mapping(void *address, size_t size)
{
    CHECK(munmap(address, size) == 0);
    unsigned char resident;
    errno = 0;
    CHECK(mincore(address, (size_t)sysconf(_SC_PAGESIZE), &resident) == -1 && errno == ENOMEM);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    int shared = !strcmp(argv[1], "shared");
    CHECK(shared || !strcmp(argv[1], "file"));
    char *end;
    long port = strtol(argv[2], &end, 10); CHECK(!*end && port > 0 && port <= 65535);
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(release && release() && !strcmp(release(), KER_NATIVE_KERNEL_RELEASE));
    errno = 0;
    CHECK(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
    int network = socket(AF_INET, SOCK_STREAM, 0); CHECK(network >= 0);
    struct timeval timeout = {.tv_sec = 10};
    CHECK(setsockopt(network, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(network, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    CHECK(inet_pton(AF_INET, "198.18.0.1", &peer.sin_addr) == 1);
    CHECK(connect(network, (struct sockaddr *)&peer, sizeof(peer)) == 0);
    long page = sysconf(_SC_PAGESIZE); CHECK(page > 0);
    size_t size = (size_t)page * 2;
    unsigned char *bytes, *witness = NULL;
    if (shared) {
        bytes = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        CHECK(bytes != MAP_FAILED);
        mapping_mode(bytes, 's');
        for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == 0);
        for (size_t i = 0; i < size; ++i) bytes[i] = pattern(i);
    } else {
        int file = mkstemp(argv[3]); CHECK(file >= 0 && file != network);
        CHECK(unlink(argv[3]) == 0 && ftruncate(file, (off_t)size) == 0);
        unsigned char *source = malloc(size); CHECK(source);
        for (size_t i = 0; i < size; ++i) source[i] = pattern(i);
        CHECK(pwrite(file, source, size, 0) == (ssize_t)size);
        free(source);
        bytes = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
        witness = mmap(NULL, size, PROT_READ, MAP_SHARED, file, 0);
        CHECK(bytes != MAP_FAILED && witness != MAP_FAILED);
        mapping_mode(bytes, 'p');
        for (size_t i = 0; i < size; ++i) CHECK(bytes[i] == pattern(i) && witness[i] == pattern(i));
        /* Closing the ordinary host fd must not close the native TCP socket;
         * both file mappings must remain usable after their fd is closed. */
        CHECK(close(file) == 0);
    }
    size_t done = 0;
    while (done < size) {
        ssize_t count = send(network, bytes + done, size - done, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
    CHECK(shutdown(network, SHUT_WR) == 0);
    done = 0;
    while (done < size) {
        ssize_t count = recv(network, bytes + done, size - done, 0);
        if (count < 0 && errno == EINTR) continue;
        CHECK(count > 0); done += (size_t)count;
    }
    unsigned char extra; CHECK(recv(network, &extra, 1, 0) == 0);
    for (size_t i = 0; i < size; ++i) {
        CHECK(bytes[i] == (unsigned char)(pattern(i) ^ 0x5a));
        if (witness) CHECK(witness[i] == pattern(i));
    }
    CHECK(close(network) == 0);
    release_mapping(bytes, size);
    if (witness) release_mapping(witness, size);
    puts("PASS: POSIX application mapping carries original-Linux TCP data and releases cleanly");
    return 0;
}
