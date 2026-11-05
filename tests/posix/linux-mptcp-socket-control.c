#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
/* Same linked adapter as both original programs. Never let a host MPTCP pass
 * stand in for an unavailable resident imported kernel. */
int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (fd >= 0) { close(fd); return 1; }
    if (errno != ENOENT) { perror("missing backend control"); return 2; }
    if (socket(AF_PACKET, SOCK_RAW, 0) >= 0 || errno != EOPNOTSUPP) return 3;
    puts("MISSING_BACKEND_REJECTED");
    return 0;
}
