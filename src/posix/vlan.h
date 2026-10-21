/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KER_NATIVE_VLAN_H
#define KER_NATIVE_VLAN_H
int ker_native_configure_vlans(int parent, int mtu, const char *settings);
int ker_native_configure_vlan_gateway6(const char *settings);
#endif
