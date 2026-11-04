#ifndef KER_MPTCP_PM_WIRE_H
#define KER_MPTCP_PM_WIRE_H
#include <stdint.h>
#define PM_MAGIC 0x4b504d31U
#define PM_MAX 16384U
/* Private, local tests-only transport. Netlink payloads are opaque Linux UAPI. */
enum pm_operation { PM_NEWNS = 1, PM_DELNS, PM_LISTNS, PM_UP, PM_SYSCTL,
    PM_SOCKET, PM_SEND, PM_RECV, PM_NAMEINDEX, PM_INDEXNAME, PM_STOP, PM_PROBE, PM_STATUS };
struct pm_message {
    uint32_t magic, operation, length, flags;
    int64_t result;
    uint32_t argument, extra;
};
_Static_assert(sizeof(struct pm_message) == 32, "private PM wire layout");
#endif
