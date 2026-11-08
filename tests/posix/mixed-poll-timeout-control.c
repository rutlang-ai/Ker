#include "mixed-poll-timeout.h"
#include <stdio.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; } } while (0)
int main(void)
{
    struct timeval timeout = {.tv_usec = 50000};
    mixed_poll_update_timeout(&timeout, 50000, 49999, 0);
    CHECK(timeout.tv_sec == 0 && timeout.tv_usec == 0);
    timeout = (struct timeval){.tv_usec = 50000};
    mixed_poll_update_timeout(&timeout, 50000, 12345, 1);
    CHECK(timeout.tv_sec == 0 && timeout.tv_usec == 37655);
    timeout = (struct timeval){.tv_usec = 50000};
    mixed_poll_update_timeout(&timeout, 50000, 12345, -1);
    CHECK(timeout.tv_sec == 0 && timeout.tv_usec == 37655);
    puts("PASS mixed poll timeout accounting");
    return 0;
}
