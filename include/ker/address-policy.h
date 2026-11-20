#ifndef KER_ADDRESS_POLICY_H
#define KER_ADDRESS_POLICY_H
#include <ker/ker.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Optional ker::address_policy. Original F-Stack callback ABI: family at the
 * callback is Linux AF_INET=2 or AF_INET6=10; caller-owned address pointers
 * and port are forwarded unchanged. Callback returns an error number,0 on
 * success, and may write the source address. No context/ownership transfer. */
typedef int (*ker_address_policy_fn)(uint16_t family, void *destination,
    uint16_t port, void *source);
/* Process-wide registration. NULL disables selection. Replacement waits for
 * all previous calls to finish, so callback code/state may then be released.
 * Returns0, or EDEADLK if called from a policy callback; registration is then
 * unchanged. Deferred cancellation of a callback releases its dispatch lease;
 * registration defers cancellation until the replacement finishes. Callbacks
 * must not longjmp out of dispatch. Not async-signal-safe. Fork only after
 * callers are quiescent. */
KER_API int ker_address_policy_register(ker_address_policy_fn callback);
/* Original ff_in_pcbladdr dispatch. Input family uses F-Stack values2/28;
 * 28 is translated to10. Unknown family with a registered callback returns
 * host EADDRNOTAVAIL. With no callback, returns0 for every family and does
 * not touch any pointer. Callback result (including non-errno markers) is
 * forwarded unchanged. The caller validates/owns its address storage.
 *
 * This is an explicit caller API, not an implicit POSIX connect hook. A
 * caller may select a source, bind it through the original Linux socket
 * API, then connect. Linux owns port allocation and all protocol behavior.
 * An all-zero source leaves source selection to that kernel. */
KER_API int ker_address_policy_select(uint16_t family, void *destination,
    uint16_t port, void *source);
#ifdef __cplusplus
}
#endif
#endif
