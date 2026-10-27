#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <lkl.h>

static long interface_query(unsigned long operation, struct ifreq *request)
{
    bool native = ker_native_ready();
    long fd = native ? lkl_sys_socket(AF_INET, SOCK_DGRAM, 0) :
        syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return native ? fd : -errno;
    long result = native ? lkl_sys_ioctl(fd, operation, (unsigned long)request) :
        syscall(SYS_ioctl, fd, operation, request);
    if (!native && result < 0) result = -errno;
    if (native) lkl_sys_close(fd); else syscall(SYS_close, fd);
    return result;
}
unsigned if_nametoindex(const char *name)
{
    size_t length = strnlen(name, IFNAMSIZ);
    if (length == IFNAMSIZ) { errno = ENODEV; return 0; }
    struct ifreq request = {0};
    memcpy(request.ifr_name, name, length + 1);
    long result = interface_query(SIOCGIFINDEX, &request);
    if (result < 0) { errno = -result; return 0; }
    return request.ifr_ifindex;
}
char *if_indextoname(unsigned index, char name[IF_NAMESIZE])
{
    if (index > INT_MAX) { errno = ENXIO; return NULL; }
    struct ifreq request = {.ifr_ifindex = (int)index};
    long result = interface_query(SIOCGIFNAME, &request);
    if (result < 0) { errno = result == -ENODEV ? ENXIO : (int)-result; return NULL; }
    memcpy(name, request.ifr_name, IF_NAMESIZE);
    return name;
}

struct interface_record { unsigned index, flags; char name[IF_NAMESIZE]; };
struct interface_records { struct interface_record *items; size_t count, capacity; };
typedef int (*dump_callback)(struct nlmsghdr *, void *);
static long route_dump(unsigned short type, dump_callback callback, void *context)
{
    long fd = lkl_sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return fd;
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    long result = lkl_sys_bind(fd, (void *)&address, sizeof(address));
    if (result < 0) goto out;
    struct {struct nlmsghdr header; struct rtgenmsg body;} request = {
        .header = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)), .nlmsg_type = type,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = 1},
        .body = {.rtgen_family = AF_UNSPEC}};
    result = lkl_sys_sendto(fd, &request, request.header.nlmsg_len, 0, (void *)&address, sizeof(address));
    if (result < 0) goto out;
    if (result != request.header.nlmsg_len) {result = -EIO; goto out;}
    bool done = false;
    while (!done) {
        long needed;
        do needed = lkl_sys_recvfrom(fd, NULL, 0, MSG_PEEK | MSG_TRUNC, NULL, NULL); while (needed == -EINTR);
        if (needed <= 0 || needed > INT_MAX) {result = needed < 0 ? needed : -EOVERFLOW; break;}
        char *buffer = malloc(needed);
        if (!buffer) {result = -ENOMEM; break;}
        struct sockaddr_nl sender; int length = sizeof(sender);
        long received;
        do received = lkl_sys_recvfrom(fd, buffer, needed, 0, (void *)&sender, &length); while (received == -EINTR);
        result = 0;
        if (received != needed || sender.nl_family != AF_NETLINK || sender.nl_pid != 0) {
            result = received < 0 ? received : -EPROTO;
        } else {
            int remaining = received;
            for (struct nlmsghdr *message = (void *)buffer; NLMSG_OK(message, remaining); message = NLMSG_NEXT(message, remaining)) {
                if (message->nlmsg_seq != 1) {result = -EPROTO; break;}
                if (message->nlmsg_flags & NLM_F_DUMP_INTR) {result = -EAGAIN; break;}
                if (message->nlmsg_type == NLMSG_DONE) {
                    if (NLMSG_PAYLOAD(message, 0) >= sizeof(int)) {
                        int status; memcpy(&status, NLMSG_DATA(message), sizeof(status)); result = status;
                    }
                    if (result > 0) result = -EPROTO;
                    done = true;
                } else if (message->nlmsg_type == NLMSG_ERROR) {
                    if (NLMSG_PAYLOAD(message, 0) < sizeof(struct nlmsgerr)) result = -EPROTO;
                    else result = ((struct nlmsgerr *)NLMSG_DATA(message))->error;
                    if (result > 0) result = -EPROTO;
                } else result = callback(message, context);
                if (result < 0) break;
            }
            if (!result && remaining) result = -EPROTO;
        }
        free(buffer);
        if (result < 0) break;
    }
out:
    lkl_sys_close(fd);
    return result;
}
static int collect_link(struct nlmsghdr *message, void *context)
{
    if (message->nlmsg_type != RTM_NEWLINK || message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) return -EPROTO;
    struct ifinfomsg *link = NLMSG_DATA(message);
    if (link->ifi_index <= 0) return -EPROTO;
    struct interface_record record = {.index = link->ifi_index, .flags = link->ifi_flags};
    int remaining = IFLA_PAYLOAD(message);
    for (struct rtattr *attribute = IFLA_RTA(link); RTA_OK(attribute, remaining); attribute = RTA_NEXT(attribute, remaining)) {
        if (attribute->rta_type != IFLA_IFNAME) continue;
        size_t length = strnlen(RTA_DATA(attribute), RTA_PAYLOAD(attribute));
        if (!length || length >= IF_NAMESIZE || length == RTA_PAYLOAD(attribute)) return -EPROTO;
        memcpy(record.name, RTA_DATA(attribute), length + 1);
    }
    if (remaining || !record.name[0] || !record.index) return -EPROTO;
    struct interface_records *records = context;
    if (records->count == records->capacity) {
        size_t capacity = records->capacity ? records->capacity * 2 : 16;
        if (capacity < records->capacity || capacity > SIZE_MAX / sizeof(record)) return -ENOMEM;
        void *next = realloc(records->items, capacity * sizeof(record));
        if (!next) return -ENOMEM;
        records->items = next; records->capacity = capacity;
    }
    records->items[records->count++] = record;
    return 0;
}
struct interface_allocation {void *pointer; struct interface_allocation *next;};
static pthread_mutex_t allocation_lock = PTHREAD_MUTEX_INITIALIZER;
static struct interface_allocation *allocations;
static int own_interfaces(void *pointer)
{
    struct interface_allocation *entry = malloc(sizeof(*entry));
    if (!entry) return -ENOMEM;
    entry->pointer = pointer;
    pthread_mutex_lock(&allocation_lock);
    entry->next = allocations; allocations = entry;
    pthread_mutex_unlock(&allocation_lock);
    return 0;
}
static bool release_interfaces(void *pointer)
{
    pthread_mutex_lock(&allocation_lock);
    struct interface_allocation **link = &allocations;
    while (*link && (*link)->pointer != pointer) link = &(*link)->next;
    struct interface_allocation *entry = *link;
    if (entry) *link = entry->next;
    pthread_mutex_unlock(&allocation_lock);
    bool owned = entry != NULL;
    free(entry);
    return owned;
}
struct if_nameindex *if_nameindex(void)
{
    if (!ker_native_ready()) {
        struct if_nameindex *(*host)(void) = dlsym(RTLD_NEXT, "if_nameindex");
        if (!host) {errno = ENOSYS; return NULL;}
        return host();
    }
    struct interface_records records = {0};
    long result = route_dump(RTM_GETLINK, collect_link, &records);
    struct if_nameindex *list = NULL;
    if (!result) {
        if (records.count > (SIZE_MAX - sizeof(*list)) / (sizeof(*list) + IF_NAMESIZE)) result = -ENOMEM;
        else {
            size_t bytes = (records.count + 1) * sizeof(*list);
            list = calloc(1, bytes + records.count * IF_NAMESIZE);
            if (!list) result = -ENOMEM;
            else {
                char *names = (char *)list + bytes;
                for (size_t i = 0; i < records.count; ++i) {
                    list[i].if_index = records.items[i].index;
                    list[i].if_name = names + i * IF_NAMESIZE;
                    memcpy(list[i].if_name, records.items[i].name, IF_NAMESIZE);
                }
                result = own_interfaces(list);
            }
        }
    }
    free(records.items);
    if (result < 0) {free(list); errno = -result; return NULL;}
    return list;
}
void if_freenameindex(struct if_nameindex *list)
{
    if (!list) return;
    if (release_interfaces(list)) {free(list); return;}
    void (*host)(struct if_nameindex *) = dlsym(RTLD_NEXT, "if_freenameindex");
    if (!host) abort();
    host(list);
}
