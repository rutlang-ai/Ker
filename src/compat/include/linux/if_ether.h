#ifndef KER_COMPAT_LINUX_IF_ETHER_H
#define KER_COMPAT_LINUX_IF_ETHER_H

/* Keep Ker's imported Linux Ethernet definitions authoritative.  Including
 * the host UAPI header here can redeclare struct ethhdr after the imported
 * Linux Ethernet adapter has already provided it. */
#include "ker/linux_ethernet.h"

#endif
