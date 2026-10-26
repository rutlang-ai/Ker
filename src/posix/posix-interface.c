#define _GNU_SOURCE
#include "fd-table.h"
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>
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

struct interface_record {
    unsigned index, flags; unsigned short hardware;
    char name[IF_NAMESIZE];
    unsigned char address[32], broadcast[32];
    size_t address_length, broadcast_length; bool have_address, have_broadcast;
    struct rtnl_link_stats statistics; bool have_statistics;
};
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
        struct sockaddr_nl sender = {0}; int length = sizeof(sender);
        long received;
        do received = lkl_sys_recvfrom(fd, buffer, needed, 0, (void *)&sender, &length); while (received == -EINTR);
        result = 0;
        if (received != needed || length < (int)sizeof(sender) || sender.nl_family != AF_NETLINK || sender.nl_pid != 0) {
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
    struct interface_record record = {.index = link->ifi_index, .flags = link->ifi_flags, .hardware = link->ifi_type};
    int remaining = IFLA_PAYLOAD(message);
    for (struct rtattr *attribute = IFLA_RTA(link); RTA_OK(attribute, remaining); attribute = RTA_NEXT(attribute, remaining)) {
        size_t length = RTA_PAYLOAD(attribute);
        if (attribute->rta_type == IFLA_IFNAME) {
            size_t characters = strnlen(RTA_DATA(attribute), length);
            if (!characters || characters >= IF_NAMESIZE || characters == length) return -EPROTO;
            memcpy(record.name, RTA_DATA(attribute), characters + 1);
        } else if (attribute->rta_type == IFLA_ADDRESS || attribute->rta_type == IFLA_BROADCAST) {
            if (length > sizeof(record.address)) return -EOVERFLOW;
            if (attribute->rta_type == IFLA_ADDRESS) {
                memcpy(record.address, RTA_DATA(attribute), length); record.address_length = length; record.have_address = true;
            } else {
                memcpy(record.broadcast, RTA_DATA(attribute), length); record.broadcast_length = length; record.have_broadcast = true;
            }
        } else if (attribute->rta_type == IFLA_STATS) {
            if (length < 6 * sizeof(unsigned)) return -EPROTO;
            if (length > sizeof(record.statistics)) length = sizeof(record.statistics);
            memcpy(&record.statistics, RTA_DATA(attribute), length); record.have_statistics = true;
        }
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

struct owned_address {
    struct ifaddrs public;
    struct sockaddr_storage address, netmask, broadcast;
    char name[IF_NAMESIZE]; struct rtnl_link_stats statistics;
};
struct address_snapshot {
    struct interface_records links;
    struct ifaddrs *head, **tail;
};
static struct owned_address *append_address(struct address_snapshot *snapshot,
    const struct interface_record *link, const char *name)
{
    struct owned_address *node = calloc(1, sizeof(*node));
    if (!node) return NULL;
    memcpy(node->name, name, IF_NAMESIZE);
    node->public.ifa_name = node->name; node->public.ifa_flags = link->flags;
    *snapshot->tail = &node->public; snapshot->tail = &node->public.ifa_next;
    return node;
}
static void packet_address(struct sockaddr_storage *storage, const struct interface_record *link,
    const unsigned char *bytes, size_t length)
{
    _Static_assert(offsetof(struct sockaddr_ll, sll_addr) + 32 <= sizeof(*storage), "hardware address storage");
    struct sockaddr_ll *address = (void *)storage;
    address->sll_family = AF_PACKET; address->sll_ifindex = link->index;
    address->sll_hatype = link->hardware; address->sll_halen = length;
    memcpy((char *)storage + offsetof(struct sockaddr_ll, sll_addr), bytes, length);
}
static void ip_address(struct sockaddr_storage *storage, int family, const unsigned char *bytes, unsigned index)
{
    if (family == AF_INET) {
        struct sockaddr_in *address = (void *)storage;
        address->sin_family = AF_INET; memcpy(&address->sin_addr, bytes, 4);
    } else {
        struct sockaddr_in6 *address = (void *)storage;
        address->sin6_family = AF_INET6; memcpy(&address->sin6_addr, bytes, 16);
        if (IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr) || IN6_IS_ADDR_MC_LINKLOCAL(&address->sin6_addr))
            address->sin6_scope_id = index;
    }
}
static int collect_address(struct nlmsghdr *message, void *context)
{
    if (message->nlmsg_type != RTM_NEWADDR || message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg))) return -EPROTO;
    struct ifaddrmsg *entry = NLMSG_DATA(message);
    if (entry->ifa_family != AF_INET && entry->ifa_family != AF_INET6) return 0;
    unsigned width = entry->ifa_family == AF_INET ? 4 : 16;
    if (entry->ifa_prefixlen > width * 8) return -EPROTO;
    struct address_snapshot *snapshot = context;
    struct interface_record *link = NULL;
    for (size_t i = 0; i < snapshot->links.count; ++i)
        if (snapshot->links.items[i].index == entry->ifa_index) {link = &snapshot->links.items[i]; break;}
    if (!link) return -EAGAIN;
    unsigned char local[16] = {0}, peer[16] = {0}, broadcast[16] = {0}, mask[16] = {0};
    bool have_local = false, have_peer = false, have_broadcast = false;
    char name[IF_NAMESIZE]; memcpy(name, link->name, sizeof(name));
    int remaining = IFA_PAYLOAD(message);
    for (struct rtattr *attribute = IFA_RTA(entry); RTA_OK(attribute, remaining); attribute = RTA_NEXT(attribute, remaining)) {
        if (attribute->rta_type == IFA_LABEL) {
            size_t length = strnlen(RTA_DATA(attribute), RTA_PAYLOAD(attribute));
            if (!length || length >= sizeof(name) || length == RTA_PAYLOAD(attribute)) return -EPROTO;
            memset(name, 0, sizeof(name)); memcpy(name, RTA_DATA(attribute), length + 1);
        } else if (attribute->rta_type == IFA_LOCAL || attribute->rta_type == IFA_ADDRESS || attribute->rta_type == IFA_BROADCAST) {
            if (RTA_PAYLOAD(attribute) < width) return -EPROTO;
            if (attribute->rta_type == IFA_LOCAL) {memcpy(local, RTA_DATA(attribute), width); have_local = true;}
            else if (attribute->rta_type == IFA_ADDRESS) {memcpy(peer, RTA_DATA(attribute), width); have_peer = true;}
            else {memcpy(broadcast, RTA_DATA(attribute), width); have_broadcast = true;}
        }
    }
    if (remaining || (!have_local && !have_peer)) return -EPROTO;
    struct owned_address *node = append_address(snapshot, link, name);
    if (!node) return -ENOMEM;
    ip_address(&node->address, entry->ifa_family, have_local ? local : peer, link->index);
    node->public.ifa_addr = (void *)&node->address;
    for (unsigned bit = 0; bit < entry->ifa_prefixlen; ++bit) mask[bit / 8] |= 0x80 >> (bit % 8);
    ip_address(&node->netmask, entry->ifa_family, mask, 0); node->public.ifa_netmask = (void *)&node->netmask;
    if ((link->flags & IFF_POINTOPOINT) && have_peer) {
        ip_address(&node->broadcast, entry->ifa_family, peer, link->index); node->public.ifa_dstaddr = (void *)&node->broadcast;
    } else if (have_broadcast) {
        ip_address(&node->broadcast, entry->ifa_family, broadcast, link->index); node->public.ifa_broadaddr = (void *)&node->broadcast;
    }
    return 0;
}
static void free_owned_addresses(struct ifaddrs *list)
{
    while (list) {struct ifaddrs *next = list->ifa_next; free(list); list = next;}
}
int getifaddrs(struct ifaddrs **output)
{
    if (!ker_native_ready()) {
        int (*host)(struct ifaddrs **) = dlsym(RTLD_NEXT, "getifaddrs");
        if (!host) {errno = ENOSYS; return -1;}
        return host(output);
    }
    if (!output) {errno = EFAULT; return -1;}
    *output = NULL;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        struct address_snapshot snapshot = {0}; snapshot.tail = &snapshot.head;
        long result = route_dump(RTM_GETLINK, collect_link, &snapshot.links);
        if (!result) for (size_t i = 0; i < snapshot.links.count; ++i) {
            struct interface_record *link = &snapshot.links.items[i];
            struct owned_address *node = append_address(&snapshot, link, link->name);
            if (!node) {result = -ENOMEM; break;}
            if (link->have_address) {
                packet_address(&node->address, link, link->address, link->address_length); node->public.ifa_addr = (void *)&node->address;
            }
            if (link->have_broadcast) {
                packet_address(&node->broadcast, link, link->broadcast, link->broadcast_length);
                node->public.ifa_broadaddr = (void *)&node->broadcast;
            }
            if (link->have_statistics) {node->statistics = link->statistics; node->public.ifa_data = &node->statistics;}
        }
        if (!result) result = route_dump(RTM_GETADDR, collect_address, &snapshot);
        free(snapshot.links.items);
        if (!result && snapshot.head) result = own_interfaces(snapshot.head);
        if (!result) {*output = snapshot.head; return 0;}
        free_owned_addresses(snapshot.head);
        if (result != -EAGAIN || attempt == 2) {errno = -result; return -1;}
    }
    errno = EAGAIN; return -1;
}
void freeifaddrs(struct ifaddrs *list)
{
    if (!list) return;
    if (release_interfaces(list)) {free_owned_addresses(list); return;}
    void (*host)(struct ifaddrs *) = dlsym(RTLD_NEXT, "freeifaddrs");
    if (!host) abort();
    host(list);
}
