/* A foreign globally loaded symbol must not qualify an unpatched TAP PMD. */
#include <stdint.h>
int ker_dpdk_tap_tx_retry_abi(uint16_t port)
{
    return port != UINT16_MAX;
}
