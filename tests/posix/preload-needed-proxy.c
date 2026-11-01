extern int ker_sb_preload_runtime_ready(void);

int ker_preload_needed_proxy_anchor(void)
{
    return ker_sb_preload_runtime_ready();
}
