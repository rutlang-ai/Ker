/* Adapt host-MM fault handling without changing original Linux usercopy users. */
#ifndef KER_LKL_UACCESS_H
#define KER_LKL_UACCESS_H
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/ker-host-usercopy.h>
static inline unsigned long raw_copy_from_user(void *to, const void __user *from, unsigned long count)
{ return ker_host_usercopy(to, (const void __force *)from, count, 0); }
static inline unsigned long raw_copy_to_user(void __user *to, const void *from, unsigned long count)
{ return ker_host_usercopy((void __force *)to, from, count, 1); }
static inline int ker_get_user_value(unsigned long size, const void __user *from, void *to)
{
    if (!raw_copy_from_user(to, from, size)) return 0;
    memset(to, 0, size);
    return -EFAULT;
}
#define __get_user_fn(size, from, to) ker_get_user_value(size, from, to)
#define __clear_user(to, count) ker_host_clear_user((void __force *)(to), count)
#define __get_kernel_nofault(dst, src, type, label) do { \
    if (ker_host_usercopy(dst, src, sizeof(type), 0)) goto label; \
} while (0)
#define __put_kernel_nofault(dst, src, type, label) do { \
    if (ker_host_usercopy(dst, src, sizeof(type), 1)) goto label; \
} while (0)
/* LKL selects the generic NOMMU memcpy optimization. That optimization is
 * inappropriate when the host MM can fault. Keep the generic implementation
 * and its string/get/put semantics, selecting our raw-copy hooks only while
 * instantiating this header; restore the original configuration afterwards. */
#ifdef CONFIG_UACCESS_MEMCPY
#if CONFIG_UACCESS_MEMCPY != 1
#error "Unexpected non-boolean UACCESS_MEMCPY configuration"
#endif
#undef CONFIG_UACCESS_MEMCPY
#define KER_UACCESS_MEMCPY_WAS_ENABLED
#endif
#include <asm-generic/uaccess.h>
#ifdef KER_UACCESS_MEMCPY_WAS_ENABLED
#define CONFIG_UACCESS_MEMCPY 1
#undef KER_UACCESS_MEMCPY_WAS_ENABLED
#endif
#endif
