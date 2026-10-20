// SPDX-License-Identifier: GPL-2.0-only
#include "ipv6-route.h"
#include <lkl.h>
#include <lkl/linux/netlink.h>
#include <lkl/linux/rtnetlink.h>
#include <netinet/in.h>
#include <stddef.h>

int ker_native_set_ipv6_gateway(int index, const struct in6_addr *gateway) {
    if (index <= 0 || !gateway)
        return -LKL_EINVAL;
    /* Supply RTA_OIF explicitly, including for a link-local next hop. Use the
     * original Linux routing implementation and its normal gateway checks;
     * do not create LKL helper per-interface policy-routing tables/rules. */
    struct {
        struct lkl_nlmsghdr header;
        struct lkl_rtmsg route;
        struct {
            struct lkl_rtattr header;
            struct in6_addr address;
        } gateway;
        struct {
            struct lkl_rtattr header;
            int index;
        } device;
    } request = {
        .header = {.nlmsg_len = sizeof(request),
                   .nlmsg_type = LKL_RTM_NEWROUTE,
                   .nlmsg_flags = LKL_NLM_F_REQUEST | LKL_NLM_F_ACK | LKL_NLM_F_CREATE | LKL_NLM_F_EXCL,
                   .nlmsg_seq = 1},
        .route = {.rtm_family = LKL_AF_INET6,
                  .rtm_table = LKL_RT_TABLE_MAIN,
                  .rtm_protocol = LKL_RTPROT_BOOT,
                  .rtm_scope = LKL_RT_SCOPE_UNIVERSE,
                  .rtm_type = LKL_RTN_UNICAST},
        .gateway = {.header = {.rta_len = LKL_RTA_LENGTH(sizeof(*gateway)), .rta_type = LKL_RTA_GATEWAY},
                    .address = *gateway},
        .device = {.header = {.rta_len = LKL_RTA_LENGTH(sizeof(index)), .rta_type = LKL_RTA_OIF},
                   .index = index},
    };
    _Static_assert(offsetof(typeof(request), gateway) == LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg)),
                   "rtnetlink gateway alignment");
    _Static_assert(sizeof(request.device) == LKL_RTA_LENGTH(sizeof(index)), "rtnetlink device length");
    int fd = lkl_sys_socket(LKL_AF_NETLINK, LKL_SOCK_RAW, LKL_NETLINK_ROUTE);
    if (fd < 0)
        return fd;
    struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
    long result;
    do {
        result = lkl_sys_sendto(fd, &request, sizeof(request), 0, (void *)&kernel, sizeof(kernel));
    } while (result == -LKL_EINTR);
    if (result == (long)sizeof(request)) {
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
