/* Host environment scenario through the actual Ker launcher/preload path. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *key = "FF_UNIT_TEST_VAR";
    const char *initial = getenv(key);
    if (!strcmp(argv[1], "--absent")) CHECK(initial == NULL);
    else CHECK(initial && !strcmp(initial, argv[1]));

    /* Application environment APIs remain POSIX APIs. No Ker-owned copy of
     * setenv/getenv is needed for the F-Stack host-helper scenario. */
    CHECK(setenv(key, "hello-world", 1) == 0);
    CHECK(getenv(key) && !strcmp(getenv(key), "hello-world"));
    CHECK(setenv(key, "must-not-replace", 0) == 0);
    CHECK(!strcmp(getenv(key), "hello-world"));

    /* This executable must actually have passed native startup. Host TCP
     * socket syscalls are denied by ker-app; binding this private address
     * also distinguishes the imported stack from the surrounding namespace. */
    const char *(*release)(void) = dlsym(RTLD_DEFAULT, "ker_posix_kernel_release");
    CHECK(release && release() && !strcmp(release(), KER_NATIVE_KERNEL_RELEASE));
    errno = 0;
    CHECK(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    CHECK(length == sizeof(address) && address.sin_family == AF_INET);
    CHECK(address.sin_addr.s_addr == inet_addr("198.18.0.2") && address.sin_port != 0);
    CHECK(close(fd) == 0);
    CHECK(unsetenv(key) == 0 && getenv(key) == NULL);
    puts("PASS: inherited environment and POSIX set/get through real native startup");
    return 0;
}
