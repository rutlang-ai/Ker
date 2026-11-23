#define _GNU_SOURCE
#include <ker/posix.h>
#include <ker/socket-broker-server.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct stop_context { int fd; };

static void *stop_listener(void *opaque)
{
	struct stop_context *context = opaque;
	char message[16];
	ssize_t amount = syscall(SYS_recvfrom, context->fd, message,
		sizeof(message), 0, NULL, NULL);
	if (amount == 4 && !memcmp(message, "STOP", 4)) ker_posix_stop_run();
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: c16-admission-broker <rpc-path> <stop-path>\n");
		return 2;
	}
	int stop_fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (stop_fd < 0) return 2;
	struct sockaddr_un stop_address = {.sun_family = AF_UNIX};
	if (strlen(argv[2]) >= sizeof(stop_address.sun_path)) return 2;
	strcpy(stop_address.sun_path, argv[2]);
	if (syscall(SYS_bind, stop_fd, &stop_address,
		(socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(argv[2]) + 1))) return 2;
	struct stop_context stop = {.fd = stop_fd};
	pthread_t stop_thread;
	if (pthread_create(&stop_thread, NULL, stop_listener, &stop)) return 2;
	struct ker_socket_broker_server *server =
		ker_socket_broker_server_create(argv[1]);
	if (!server) {
		fprintf(stderr, "broker create: %s\n", strerror(errno));
		return 1;
	}
	puts("C16_BROKER_READY");
	fflush(stdout);
	int result = ker_socket_broker_server_run(server, 0);
	int saved = errno;
	(void)pthread_join(stop_thread, NULL);
	(void)syscall(SYS_close, stop_fd);
	(void)syscall(SYS_unlinkat, AT_FDCWD, argv[2], 0);
	if (getenv("KER_C28_TEST_CHECKED_DESTROY")) {
		if (getenv("KER_C28_TEST_PREARM_FAILURE")) {
			if (result != 0 || ker_socket_broker_server_destroy_checked(server) != 0) {
				fprintf(stderr, "C28 pre-ARM failure did not clean up: %s\n",
					strerror(errno));
				return 1;
			}
			puts("C28_PREARM_FAILURE_CLEAN no-arm/no-pins");
			fflush(stdout);
			puts("C16_BROKER_DONE");
			return 0;
		}
		if (result != -1 || saved != EBUSY) {
			fprintf(stderr, "C28 expected run shutdown to retain a live runtime: %s\n",
				strerror(saved));
			return 1;
		}
		if (ker_socket_broker_server_destroy_checked(server) != -1 || errno != EBUSY) {
			fprintf(stderr, "C28 checked destroy failed to retain unresolved quarantine: %s\n",
				strerror(errno));
			return 1;
		}
		puts("C28_DESTROY_EBUSY controller-and-fd-pins-retained");
		fflush(stdout);
		const char *release = getenv("KER_C28_TEST_QUARANTINE_GATE");
		struct timespec pause = {.tv_nsec = 10000000};
		unsigned attempt;
		for (attempt = 0; release && attempt < 1000 &&
			syscall(SYS_access, release, F_OK) != 0;
			++attempt) {
			while (nanosleep(&pause, &pause) && errno == EINTR) { }
			pause.tv_nsec = 10000000;
		}
		if (!release || syscall(SYS_access, release, F_OK) != 0) {
			fprintf(stderr, "C28 quarantine retry gate was not released\n");
			return 1;
		}
		/* Same callback/context is a cleanup-only continuation after the first
		 * run retained the live kernel because quarantine was unconfirmed. */
		if (ker_socket_broker_server_run(server, 0) != 0 ||
			ker_socket_broker_server_destroy_checked(server) != 0) {
			fprintf(stderr, "C28 checked destroy retry did not confirm quarantine: %s\n",
				strerror(errno));
			return 1;
		}
		puts("C28_DESTROY_RETRY_OK quarantine-confirmed/pins-released");
		fflush(stdout);
		result = 0;
	} else {
		ker_socket_broker_server_destroy(server);
	}
	if (result) {
		errno = saved;
		fprintf(stderr, "broker run: %s\n", strerror(errno));
		return 1;
	}
	puts("C16_BROKER_DONE");
	return 0;
}
