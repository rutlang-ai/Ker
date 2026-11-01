#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include "ff-owner-admission-control.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	struct ker_socket_client client = {0};
	if (ker_socket_client_open(&client, argv[1])) return 1;
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
