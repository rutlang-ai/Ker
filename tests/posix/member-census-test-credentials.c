#define _GNU_SOURCE
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/capability.h>
#include <link.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static _Thread_local struct __lkl__user_cap_header_struct saved_header;
static _Thread_local struct __lkl__user_cap_data_struct saved_data[2];
static _Thread_local bool saved;

struct runtime_map_counts { unsigned test_runtime; unsigned production_runtime; };

static int count_runtime_maps(struct dl_phdr_info *info, size_t size, void *opaque)
{
    (void)size;
    struct runtime_map_counts *counts = opaque;
    if (strstr(info->dlpi_name, "libker-posix-member-census-test-runtime.so"))
        ++counts->test_runtime;
    if (strstr(info->dlpi_name, "libker-posix.so")) ++counts->production_runtime;
    return 0;
}

int ker_member_census_test_runtime_map_counts(unsigned *test_runtime,
    unsigned *production_runtime)
{
    if (!test_runtime || !production_runtime) return -EINVAL;
    struct runtime_map_counts counts = {0};
    dl_iterate_phdr(count_runtime_maps, &counts);
    *test_runtime = counts.test_runtime;
    *production_runtime = counts.production_runtime;
    return 0;
}

int ker_member_census_test_clear_net_admin(void)
{
    if (saved) return -EBUSY;
    saved_header.version = _LKL_LINUX_CAPABILITY_VERSION_3;
    saved_header.pid = 0;
    long result = lkl_sys_capget(&saved_header, saved_data);
    if (result < 0) return (int)result;
    unsigned int word = LKL_CAP_NET_ADMIN / 32;
    uint32_t mask = UINT32_C(1) << (LKL_CAP_NET_ADMIN % 32);
    if (!(saved_data[word].effective & mask)) return -EPERM;
    struct __lkl__user_cap_data_struct restricted[2];
    memcpy(restricted, saved_data, sizeof(restricted));
    restricted[word].effective &= ~mask;
    result = lkl_sys_capset(&saved_header, restricted);
    if (result < 0) return (int)result;
    saved = true;
    return 0;
}

int ker_member_census_test_restore_capabilities(void)
{
    if (!saved) return -EINVAL;
    long result = lkl_sys_capset(&saved_header, saved_data);
    if (result < 0) return (int)result;
    memset(saved_data, 0, sizeof(saved_data));
    saved = false;
    return 0;
}
