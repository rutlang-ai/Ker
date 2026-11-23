// SPDX-License-Identifier: GPL-2.0-only
#include "ipv6-route.h"
#include <lkl.h>
#include <lkl/linux/netlink.h>
#include <lkl/linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>

static int set_gateway(int index, int family, const void *gateway, unsigned int size) {
    if (index <= 0 || !gateway || (size != 4 && size != 16))
        return -LKL_EINVAL;
    /* Explicit RTA_OIF selects the VLAN while preserving the main routing
     * table. Original Linux validates the gateway and owns route selection. */
    struct {
        struct lkl_nlmsghdr header;
        struct lkl_rtmsg route;
        unsigned char attributes[32];
    } request = {
        .header = {.nlmsg_len = LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg)),
                   .nlmsg_type = LKL_RTM_NEWROUTE,
                   .nlmsg_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_ACK | LKL_NLM_F_CREATE | LKL_NLM_F_EXCL,
                   .nlmsg_seq = 1},
        .route = {.rtm_family = family,
                  .rtm_table = LKL_RT_TABLE_MAIN,
                  .rtm_protocol = LKL_RTPROT_BOOT,
                  .rtm_scope = LKL_RT_SCOPE_UNIVERSE,
                  .rtm_type = LKL_RTN_UNICAST},
    };
    struct lkl_rtattr *attribute = (void *)request.attributes;
    attribute->rta_type = LKL_RTA_GATEWAY;
    attribute->rta_len = LKL_RTA_LENGTH(size);
    memcpy(LKL_RTA_DATA(attribute), gateway, size);
    request.header.nlmsg_len += LKL_RTA_ALIGN(attribute->rta_len);
    attribute = (void *)((unsigned char *)&request + request.header.nlmsg_len);
    attribute->rta_type = LKL_RTA_OIF;
    attribute->rta_len = LKL_RTA_LENGTH(sizeof(index));
    memcpy(LKL_RTA_DATA(attribute), &index, sizeof(index));
    request.header.nlmsg_len += LKL_RTA_ALIGN(attribute->rta_len);
    int fd = lkl_sys_socket(LKL_AF_NETLINK, LKL_SOCK_RAW, LKL_NETLINK_ROUTE);
    if (fd < 0)
        return fd;
    struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
    long result;
    do {
        result = lkl_sys_sendto(fd, &request, request.header.nlmsg_len, 0, (void *)&kernel, sizeof(kernel));
    } while (result == -LKL_EINTR);
    if (result == (long)request.header.nlmsg_len) {
        union {
            struct lkl_nlmsghdr align;
            unsigned char bytes[4096];
        } reply;
        do {
            result = lkl_sys_recvfrom(fd, &reply, sizeof(reply), 0, NULL, NULL);
        } while (result == -LKL_EINTR);
        if (result >= 0) {
            int length = (int)result;
            struct lkl_nlmsghdr *header = &reply.align;
            result = -LKL_EIO;
            for (; LKL_NLMSG_OK(header, length); header = LKL_NLMSG_NEXT(header, length)) {
                if (header->nlmsg_seq != request.header.nlmsg_seq)
                    continue;
                if (header->nlmsg_type == LKL_NLMSG_ERROR &&
                    header->nlmsg_len >= LKL_NLMSG_LENGTH(sizeof(struct lkl_nlmsgerr))) {
                    struct lkl_nlmsgerr *error = LKL_NLMSG_DATA(header);
                    result = error->error;
                    break;
                }
            }
        }
    } else if (result >= 0)
        result = -LKL_EIO;
    long closed = lkl_sys_close(fd);
    return (int)(result ? result : closed);
}

int ker_native_set_ipv6_gateway(int index, const struct in6_addr *gateway) {
    return set_gateway(index, LKL_AF_INET6, gateway, sizeof(*gateway));
}

int ker_native_set_ipv4_gateway(int index, const struct in_addr *gateway) {
    return set_gateway(index, LKL_AF_INET, gateway, sizeof(*gateway));
}
