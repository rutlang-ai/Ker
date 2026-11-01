#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define C15_MARK UINT32_C(0x4c150001)

extern int ker_c15_admission_test_run(int listener_fd, const char *prefix);

int main(void)
{
	const char *prefix = getenv("KER_C15_ADMISSION_CONTROL");
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(8080),
	};
	int listener = -1;
	if (!prefix || !*prefix || inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) != 1) {
		fputs("C15 TAP client: missing control path or bad fixture address\n", stderr);
		return 2;
	}
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_MARK,
		&(uint32_t){C15_MARK}, sizeof(uint32_t)) ||
		bind(listener, (struct sockaddr *)&address, sizeof(address))) {
		perror("C15 TAP socket setup");
		if (listener >= 0) close(listener);
		return 2;
	}
	int result = ker_c15_admission_test_run(listener, prefix);
	if (result) {
		fprintf(stderr, "C15 TAP admission runtime failed: %d\n", result);
		return 1;
	}
	puts("C15_TAP_ADMISSION_POSITIVE_OK");
	return 0;
}
