#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include "ff-owner-admission-control.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2 && argc != 3) return 2;
	struct ker_socket_client client = {0};
	if (ker_socket_client_open(&client, argv[1])) return 1;
	if (argc == 3 && !strcmp(argv[2], "ordinary-tfo")) {
		int ordinary = ker_socket_client_socket(&client, AF_INET,
			SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
		struct sockaddr_in address = {.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
		int fastopen = 1;
		if (ordinary < 0 || ker_socket_client_bind(&client, ordinary,
				(const struct sockaddr *)&address, sizeof(address)) ||
		    ker_socket_client_listen(&client, ordinary, 1) ||
		    ker_socket_client_setsockopt(&client, ordinary, IPPROTO_TCP,
				TCP_FASTOPEN, &fastopen, sizeof(fastopen))) {
			int error = errno ? errno : EPROTO;
			if (ordinary >= 0) (void)syscall(SYS_close, ordinary);
			ker_socket_client_close(&client);
			errno = error;
			perror("C16 ordinary TCP_FASTOPEN option");
			return 1;
		}
		socklen_t fastopen_length = sizeof(fastopen);
		fastopen = 0;
		if (ker_socket_client_getsockopt(&client, ordinary, IPPROTO_TCP,
				TCP_FASTOPEN, &fastopen, &fastopen_length) ||
		    fastopen_length != sizeof(fastopen) || fastopen < 1) {
			int error = errno ? errno : EPROTO;
			(void)syscall(SYS_close, ordinary);
			ker_socket_client_close(&client);
			errno = error;
			perror("C16 ordinary TCP_FASTOPEN readback");
			return 1;
		}
		(void)syscall(SYS_close, ordinary);
		ker_socket_client_close(&client);
		puts("C16_ORDINARY_TFO_OK enabled=1");
		return 0;
	}
	int owner = ker_socket_client_ff_owner_create(&client);
	if (owner < 0) return 1;
	int socket_cap = ker_socket_client_ff_owner_socket(&client, owner,
		AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (socket_cap < 0) {
		int error = errno;
		(void)syscall(SYS_close, owner);
		ker_socket_client_close(&client);
		errno = error;
		perror("C16 unrelated owner socket RPC");
		return 1;
	}
	(void)syscall(SYS_close, socket_cap);
	/* Admission registration is permanently closed after any owned socket
	 * activity, even when its last descriptor has been closed. */
	struct ker_ff_owner_admission_registration registration;
	struct ker_ff_owner_admission_registration untouched;
	memset(&registration, 0xa5, sizeof(registration));
	memcpy(&untouched, &registration, sizeof(untouched));
	errno = 0;
	if (ker_socket_client_ff_owner_admission_prepare(&client, owner,
			&registration) != -1 || errno != EBUSY ||
	    memcmp(&registration, &untouched, sizeof(registration))) {
		int error = errno ? errno : EPROTO;
		(void)syscall(SYS_close, owner);
		ker_socket_client_close(&client);
		errno = error;
		perror("C16 closed-socket history guard");
		return 1;
	}
	(void)syscall(SYS_close, owner);
	ker_socket_client_close(&client);
	puts("C16_RPC_PROGRESS_OK history=EBUSY");
	return 0;
}
