// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "vlan.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lkl.h>
#include <lkl/linux/if_link.h>
#include <lkl/linux/netlink.h>
#include <lkl/linux/rtnetlink.h>

struct request {
    struct lkl_nlmsghdr header;
    struct lkl_ifinfomsg interface;
    unsigned char attributes[256];
};
static struct lkl_rtattr *attribute(struct request *request, unsigned short type,
                                  const void *data, unsigned short length)
{
    size_t offset = LKL_NLMSG_ALIGN(request->header.nlmsg_len);
    size_t size = LKL_RTA_LENGTH(length);
    if (offset + LKL_RTA_ALIGN(size) > sizeof(*request)) return NULL;
    struct lkl_rtattr *result = (void *)((unsigned char *)request + offset);
    result->rta_type = type;
    result->rta_len = size;
    if (length) memcpy(LKL_RTA_DATA(result), data, length);
    request->header.nlmsg_len = offset + LKL_RTA_ALIGN(size);
    return result;
}
static int create_vlan(int parent, uint16_t tag, const char *name)
{
    struct request request = {
        .header = {.nlmsg_len = LKL_NLMSG_LENGTH(sizeof(struct lkl_ifinfomsg)),
                   .nlmsg_type = LKL_RTM_NEWLINK, .nlmsg_seq = 1,
                   .nlmsg_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_ACK | LKL_NLM_F_CREATE | LKL_NLM_F_EXCL},
        .interface = {.ifi_family = LKL_AF_UNSPEC},
    };
    if (!attribute(&request, LKL_IFLA_LINK, &parent, sizeof(parent)) ||
        !attribute(&request, LKL_IFLA_IFNAME, name, strlen(name) + 1)) return -LKL_E2BIG;
    struct lkl_rtattr *link = attribute(&request, LKL_IFLA_LINKINFO | LKL_NLA_F_NESTED, NULL, 0);
    if (!link || !attribute(&request, LKL_IFLA_INFO_KIND, "vlan", 5)) return -LKL_E2BIG;
    struct lkl_rtattr *data = attribute(&request, LKL_IFLA_INFO_DATA | LKL_NLA_F_NESTED, NULL, 0);
    if (!data || !attribute(&request, LKL_IFLA_VLAN_ID, &tag, sizeof(tag))) return -LKL_E2BIG;
    data->rta_len = (unsigned char *)&request + request.header.nlmsg_len - (unsigned char *)data;
    link->rta_len = (unsigned char *)&request + request.header.nlmsg_len - (unsigned char *)link;
    int fd = lkl_sys_socket(LKL_AF_NETLINK, LKL_SOCK_RAW, LKL_NETLINK_ROUTE);
    if (fd < 0) return fd;
    struct lkl_sockaddr_nl destination = {.nl_family = LKL_AF_NETLINK};
    long result;
    do result = lkl_sys_sendto(fd, &request, request.header.nlmsg_len, 0, (void *)&destination, sizeof(destination));
    while (result == -LKL_EINTR);
    if (result == request.header.nlmsg_len) {
        union { struct lkl_nlmsghdr align; unsigned char bytes[4096]; } reply;
        do result = lkl_sys_recvfrom(fd, &reply, sizeof(reply), 0, NULL, NULL);
        while (result == -LKL_EINTR);
        if (result >= 0) {
            int length = result;
            struct lkl_nlmsghdr *header = &reply.align;
            result = -LKL_EIO;
            for (; LKL_NLMSG_OK(header, length); header = LKL_NLMSG_NEXT(header, length)) {
                if (header->nlmsg_seq == 1 && header->nlmsg_type == LKL_NLMSG_ERROR &&
                    header->nlmsg_len >= LKL_NLMSG_LENGTH(sizeof(struct lkl_nlmsgerr))) {
                    result = ((struct lkl_nlmsgerr *)LKL_NLMSG_DATA(header))->error;
                    break;
                }
            }
        }
    } else if (result >= 0) result = -LKL_EIO;
    long closed = lkl_sys_close(fd);
    return (int)(result ? result : closed);
}
int ker_native_configure_vlans(int parent, int mtu, const char *settings)
{
    if (!settings || !*settings) return 0;
    if (parent <= 0 || mtu < 1280 || mtu > 9000 || strlen(settings) > 4096) return -LKL_EINVAL;
    char *copy = strdup(settings);
    if (!copy) return -LKL_ENOMEM;
    int result = 0;
    unsigned int count = 0;
    char *state, *entry = strtok_r(copy, ";", &state);
    while (entry && !result) {
        char *addresses = strchr(entry, '=');
        if (!addresses || ++count > 16) { result = -LKL_EINVAL; break; }
        *addresses++ = 0;
        char *end;
        errno = 0;
        long tag = strtol(entry, &end, 10);
        if (errno || !*entry || *end || tag < 1 || tag > 4094) { result = -LKL_EINVAL; break; }
        char name[16];
        snprintf(name, sizeof(name), "ker.%ld", tag);
        result = create_vlan(parent, (uint16_t)tag, name);
        int index = result ? result : lkl_ifname_to_ifindex(name);
        if (index <= 0) { result = index ? index : -LKL_ENODEV; break; }
        unsigned int address_count = 0;
        char *address_state, *address = strtok_r(addresses, ",", &address_state);
        while (address && !result) {
            char *prefix = strchr(address, '/');
            if (!prefix || ++address_count > 8) { result = -LKL_EINVAL; break; }
            *prefix++ = 0;
            struct in_addr ipv4;
            long bits = strtol(prefix, &end, 10);
            if (!*prefix || *end || bits < 0 || bits > 32 || inet_pton(AF_INET, address, &ipv4) != 1) {
                result = -LKL_EINVAL; break;
            }
            result = lkl_if_set_ipv4(index, ipv4.s_addr, (unsigned int)bits);
            address = strtok_r(NULL, ",", &address_state);
        }
        if (!result && !address_count) result = -LKL_EINVAL;
        if (!result) result = lkl_if_set_mtu(index, mtu);
        if (!result) result = lkl_if_up(index);
        entry = strtok_r(NULL, ";", &state);
    }
    free(copy);
    return result;
}
