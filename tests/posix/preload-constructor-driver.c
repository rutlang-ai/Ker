#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

extern int ker_preload_constructor_probe_anchor(void);

int main(void)
{
    if (ker_preload_constructor_probe_anchor() != 1) return 1;
    typedef int (*runtime_ready_fn)(void);
    runtime_ready_fn runtime_ready = (runtime_ready_fn)dlsym(RTLD_DEFAULT,
        "ker_sb_preload_runtime_ready");
    if (!runtime_ready || runtime_ready() != 1) return 2;
    fputs("PRELOAD_CONSTRUCTOR_MAIN_OK\n", stdout);
    return 0;
}
