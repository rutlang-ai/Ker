#ifndef KER_BOND_POLICY_H
#define KER_BOND_POLICY_H
#include <stdint.h>
/* Optional original PMD API, resolved only for typed bond deployments. */
int ker_bond_policy_apply(uint16_t port, const char *policy);
int ker_bond_members(uint16_t port, uint16_t *ids, uint16_t capacity);
int ker_bond_snapshot(uint16_t port, char *json, unsigned size);
#endif
