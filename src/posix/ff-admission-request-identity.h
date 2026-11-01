#ifndef KER_FF_ADMISSION_REQUEST_IDENTITY_H
#define KER_FF_ADMISSION_REQUEST_IDENTITY_H

#include "tcp-request-revoke.h"

#include <stdatomic.h>
#include <stdint.h>
#include <netinet/in.h>

struct ker_ff_admission_request_identity;

/* Full IPv4 tuple observed from the admitted packet, in network byte order.
 * `local` must be a concrete destination address; this also supports a
 * wildcard-bound listener after the packet's destination is known. */
struct ker_ff_admission_ipv4_tuple {
	struct sockaddr_in local;
	struct sockaddr_in remote;
};

/* Private LKL adapter. `listener_fd` is an application descriptor managed by
 * the native POSIX fd table, not a raw LKL descriptor. The context retains its
 * socket entry until close and checks that the application descriptor still
 * names that entry before and after each dump. The caller must also recheck
 * its listener ownership before issuing a packet verdict. The
 * expected mark is supplied by the privileged FF caller; this leaf does not
 * authenticate a process or derive ownership. The caller must enforce one
 * listener per owner mark because inet_diag request rows do not identify
 * their parent listener. The downstream C14 revoke ioctl validates the
 * saved listener cookie against the actual request parent. */
int ker_ff_admission_request_identity_begin(int listener_fd,
	const struct ker_ff_admission_ipv4_tuple *tuple, uint32_t expected_mark,
	struct ker_ff_admission_request_identity **output);

/* Returns 0 while no unique request is present, 1 after a complete validated
 * dump produced an exact request identity, or negative errno. The request
 * output is unchanged unless 1 is returned. Cancellation is terminal and
 * closes the internal netlink fd; close() releases the context allocation.
 * The leaf has a 5-second absolute bound; packet callers with a shorter
 * deadline must set cancel when that deadline expires. */
int ker_ff_admission_request_identity_step(
	struct ker_ff_admission_request_identity *identity,
	const atomic_bool *cancel,
	struct ker_tcp_request_revoke_request *request);

/* Recheck the same live app listener after a complete result and immediately
 * before the caller issues a packet verdict. The caller must serialize its
 * verdict decision against listener close/replacement. */
int ker_ff_admission_request_identity_revalidate(
	struct ker_ff_admission_request_identity *identity);

void ker_ff_admission_request_identity_close(
	struct ker_ff_admission_request_identity *identity);

#endif
