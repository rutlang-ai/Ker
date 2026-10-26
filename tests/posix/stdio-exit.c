#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static char buffer[512];
static const char payload[] = "buffered-native-exit\n";
int main(int argc, char **argv)
{
    CHECK(argc == 4);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(argv[3]))};
    CHECK(inet_pton(AF_INET, argv[2], &address.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); CHECK(fd >= 0);
    int failing = strstr(argv[1], "-error") != NULL;
    if (!strcmp(argv[1], "server") || !strcmp(argv[1], "server-error")) {
        int one = 1; CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0);
        CHECK(bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 1) == 0);
        printf("READY %s\n", argv[3]); CHECK(fflush(stdout) == 0);
        int peer = accept(fd, NULL, NULL); CHECK(peer >= 0);
        char received[128]; size_t used = 0;
        for (;;) {
            CHECK(used < sizeof(received));
            ssize_t count = recv(peer, received + used, sizeof(received) - used, 0);
            CHECK(count >= 0); if (!count) break; used += (size_t)count;
        }
        CHECK(used == (failing ? 0 : sizeof(payload) - 1) && !memcmp(received, payload, used));
        CHECK(close(peer) == 0 && close(fd) == 0);
        puts(failing ? "PASS: independent host saw failed buffered stream EOF without payload" :
            "PASS: independent host received exact buffered exit payload and EOF");
    } else {
        CHECK(!strcmp(argv[1], "client") || !strcmp(argv[1], "client-error"));
        CHECK(connect(fd, (void *)&address, sizeof(address)) == 0);
        FILE *stream = fdopen(fd, "w"); CHECK(stream && fileno(stream) == fd);
        CHECK(setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) == 0);
        if (failing) {
            struct sigaction ignore = {.sa_handler = SIG_IGN}; sigemptyset(&ignore.sa_mask);
            CHECK(sigaction(SIGPIPE, &ignore, NULL) == 0 && shutdown(fd, SHUT_WR) == 0);
        }
        CHECK(fwrite(payload, 1, sizeof(payload) - 1, stream) == sizeof(payload) - 1);
        /* Intentionally leave the stream buffered and open until normal exit. */
        puts("PASS: application returns with buffered native FILE output");
        CHECK(fflush(stdout) == 0);
    }
    return 0;
}
