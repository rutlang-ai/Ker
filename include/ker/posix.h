#ifndef KER_POSIX_H
#define KER_POSIX_H
#include <ker/ker.h>
#ifdef __cplusplus
extern "C" {
#endif
/* These queries belong to the optional ker::posix component, initialized by
 * ker-run. The standard socket APIs are declared by the system POSIX headers. */
KER_API uint64_t ker_posix_capabilities(void);
/* Process-lifetime string, or NULL while the native instance is inactive. */
KER_API const char *ker_posix_kernel_release(void);
/* Read the active original Linux CLOCK_REALTIME. Each output is optional.
 * Returns 0 on success or -1 with errno and leaves outputs intact on failure.
 * An inactive instance reports ENETDOWN. Quiesce callers before shutdown. */
KER_API int ker_posix_get_current_time(int64_t *seconds, long *nanoseconds);
#ifdef __cplusplus
}
#endif
#endif
