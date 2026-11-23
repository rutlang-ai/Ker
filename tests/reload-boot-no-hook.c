#define _DEFAULT_SOURCE
#include <rte_ethdev.h>
#include <stdio.h>
const struct rte_eth_rxtx_callback *__wrap_rte_eth_add_tx_callback(uint16_t port,
    uint16_t queue, rte_tx_callback_fn callback, void *argument)
{
    (void)port; (void)queue; (void)callback; (void)argument;
    fputs("RELOAD_BOOT_HOOK_ALLOCATION_FAILED\n", stderr);
    return NULL;
}
