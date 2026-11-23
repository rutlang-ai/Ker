#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "environment contract: %s\n", #x); return 1; } } while (0)
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *preload = getenv("LD_PRELOAD");
    CHECK(preload && strcmp(preload, argv[1]) == 0);
    CHECK(getenv("KER_PRELOAD_LIBRARY") == NULL);
    const char *inherited = getenv("KER_TEST_ENVIRONMENT_VALUE");
    CHECK(inherited && strcmp(inherited, "hello-world") == 0);
    uint64_t (*capabilities)(void) = (uint64_t (*)(void))dlsym(RTLD_DEFAULT, "ker_posix_capabilities");
    CHECK(capabilities && capabilities());
    /* This runs after ker-app's real setenv + exec and the native constructor.
     * The app guard forbids host TCP, so a successful exchange needs Linux. */
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (void *)&address, &length) == 0 && address.sin_port);
    int sender = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(sender >= 0);
    CHECK(connect(sender, (void *)&address, sizeof(address)) == 0);
    int receiver = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    CHECK(receiver >= 0);
    struct timeval timeout = {.tv_sec = 2};
    CHECK(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    const char payload[] = "environment-native-tcp";
    CHECK(send(sender, payload, sizeof(payload), MSG_NOSIGNAL) == sizeof(payload));
    char received[sizeof(payload)];
    CHECK(recv(receiver, received, sizeof(received), MSG_WAITALL) == sizeof(received));
    CHECK(memcmp(received, payload, sizeof(payload)) == 0);
    CHECK(close(receiver) == 0 && close(sender) == 0 && close(listener) == 0);
    puts("PASS: ker-app environment roundtrip, internal-key removal and original Linux TCP");
    return 0;
}
