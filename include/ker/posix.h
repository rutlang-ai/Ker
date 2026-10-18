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
#ifdef __cplusplus
}
#endif
#endif
