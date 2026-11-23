/*
 * Ker qualification adapter for the pinned upstream Nginx flow-map source.
 * The included file is checksum-pinned by CMake and is not copied or patched.
 * This TU hides its incidental Nginx globals and exports only the gated arm
 * entry point used by the private source-classifier fixture.
 */
#include <ngx_auto_config.h>
#include <ff_api.h>
#include <ff_config.h>
#include <ff_reload.h>

#ifndef KER_PINNED_NGINX_FF_MODULE_SOURCE
#error "CMake must supply the pinned ngx_ff_module.c path"
#endif

#include KER_PINNED_NGINX_FF_MODULE_SOURCE

__attribute__((visibility("default")))
int ker_nginx_original_flow_map_arm(void)
{
    if (!ff_reload_state_attached() ||
        ff_reload_gen() != ff_reload_target_gen() ||
        !ff_reload_hw_locked())
        return -ESTALE;

    ngx_ff_flow_map_arm();
    return ff_flow_map_active() ? 0 : -EIO;
}
