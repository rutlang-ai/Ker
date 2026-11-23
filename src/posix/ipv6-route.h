// SPDX-License-Identifier: GPL-2.0-only
#pragma once
struct in6_addr;
/* Install a default route in the private Linux main table, via this device. */
int ker_native_set_ipv6_gateway(int index, const struct in6_addr *gateway);

struct in_addr;
int ker_native_set_ipv4_gateway(int index, const struct in_addr *gateway);
