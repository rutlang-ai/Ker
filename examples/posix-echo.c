/* An ordinary POSIX program: build and run with the host, or launch with ker-run. */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s IPv4 PORT\n", argv[0]); return 2; }
    char *end;
    long port = strtol(argv[2], &end, 10);
    struct sockaddr_in address = {.sin_family = AF_INET};
    if (!*argv[2] || *end || port < 1 || port > 65535 ||
        inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) return 2;
    address.sin_port = htons((unsigned short)port);
    signal(SIGPIPE, SIG_IGN);
    int listener = socket(AF_INET, SOCK_STREAM, 0), peer = -1, status = 1;
    if (listener < 0) goto done;
    int one = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
        bind(listener, (void *)&address, sizeof(address)) || listen(listener, 16)) goto done;
    printf("Listening on %s:%ld (one connection)\n", argv[1], port);
    fflush(stdout);
    peer = accept(listener, NULL, NULL);
    if (peer < 0) goto done;
    char bytes[16384];
    for (;;) {
        ssize_t count = read(peer, bytes, sizeof(bytes));
        if (count < 0) { if (errno == EINTR) continue; goto done; }
        if (!count) break;
        for (ssize_t sent = 0; sent < count;) {
            ssize_t n = write(peer, bytes + sent, (size_t)(count - sent));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) goto done;
            sent += n;
        }
    }
    if (shutdown(peer, SHUT_WR)) goto done;
    status = 0;
done:
    if (status) perror("POSIX echo");
    if (peer >= 0) close(peer);
    if (listener >= 0) close(listener);
    return status;
}
