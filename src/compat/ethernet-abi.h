#ifndef KER_COMPAT_ETHERNET_ABI_H
#define KER_COMPAT_ETHERNET_ABI_H

#include <stddef.h>
#include "ker/linux_ethernet.h"

/* Neighbor adapters use the pinned Linux Ethernet projection. Keep the
 * kernel wire layout explicit instead of picking up a host UAPI ethhdr. */
_Static_assert(ETH_ALEN == 6, "pinned Linux ETH_ALEN changed");
_Static_assert(ETH_HLEN == 14, "pinned Linux ETH_HLEN changed");
_Static_assert(sizeof(struct ethhdr) == ETH_HLEN, "pinned Linux ethhdr size changed");
_Static_assert(offsetof(struct ethhdr, h_dest) == 0, "pinned Linux ethhdr destination offset changed");
_Static_assert(offsetof(struct ethhdr, h_source) == ETH_ALEN, "pinned Linux ethhdr source offset changed");
_Static_assert(offsetof(struct ethhdr, h_proto) == 2 * ETH_ALEN, "pinned Linux ethhdr protocol offset changed");

#endif
