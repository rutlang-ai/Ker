#include <stddef.h>
#include <stdint.h>

#include <asm/ker_tcp_request_revoke.h>

_Static_assert(sizeof(struct ker_tcp_request_revoke_request) == 72,
	"private TCP request-revoke ABI size must stay fixed");
_Static_assert(offsetof(struct ker_tcp_request_revoke_request, local_port) == 16,
	"tuple ports must keep their fixed offset");
_Static_assert(offsetof(struct ker_tcp_request_revoke_request, local_address) == 24,
	"tuple addresses must keep their fixed offset");
_Static_assert(offsetof(struct ker_tcp_request_revoke_request, request_cookie) == 56,
	"request cookie must keep its fixed offset");
_Static_assert(offsetof(struct ker_tcp_request_revoke_request, listener_cookie) == 64,
	"listener cookie must keep its fixed offset");
_Static_assert(_IOC_SIZE(KER_TCP_REQUEST_REVOKE) == 72,
	"ioctl size must match the fixed private ABI");

int main(void)
{
	return 0;
}
