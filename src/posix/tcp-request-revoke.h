#ifndef KER_TCP_REQUEST_REVOKE_H
#define KER_TCP_REQUEST_REVOKE_H

#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_tcp_request_revoke.h"

/* Private in-process adapter for Ker's authenticated broker. The caller is
 * responsible for deriving mark and cookies from trusted broker metadata. */
int ker_native_tcp_request_revoke(
	const struct ker_tcp_request_revoke_request *request);

#endif
