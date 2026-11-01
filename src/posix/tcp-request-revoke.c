#define _GNU_SOURCE
#include "tcp-request-revoke.h"

#include <errno.h>
#include <lkl.h>
#include <lkl/linux/stat.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define KER_TCP_REQUEST_REVOKE_DEVICE_NAME "ker-tcp-request-revoke"
#define KER_TCP_REQUEST_REVOKE_PROC_MISC_MAX 8192U
#define KER_TCP_REQUEST_REVOKE_MISC_MINOR_MAX ((1U << 20) - 1)

_Static_assert(sizeof(struct ker_tcp_request_revoke_request) == 72,
	"private TCP request-revoke ioctl ABI must be 72 bytes");

static _Atomic unsigned int ker_tcp_request_revoke_sequence;

static int find_misc_minor(unsigned int *minor)
{
	char buffer[KER_TCP_REQUEST_REVOKE_PROC_MISC_MAX + 1];
	long fd = lkl_sys_open("/proc/misc", LKL_O_RDONLY | LKL_O_CLOEXEC, 0);
	size_t used = 0;
	long result;
	bool found = false;

	if (fd < 0)
		return (int)fd;
	for (;;) {
		result = lkl_sys_read((unsigned int)fd, buffer + used,
			KER_TCP_REQUEST_REVOKE_PROC_MISC_MAX - used);
		if (result < 0)
			break;
		if (!result) {
			result = 0;
			break;
		}
		used += (size_t)result;
		if (used == KER_TCP_REQUEST_REVOKE_PROC_MISC_MAX) {
			char extra;
			long more = lkl_sys_read((unsigned int)fd, &extra, 1);
			result = more < 0 ? more : more ? -E2BIG : 0;
			break;
		}
	}
	long closed = lkl_sys_close((unsigned int)fd);
	if (result < 0)
		return (int)result;
	if (closed < 0)
		return (int)closed;
	buffer[used] = '\0';

	char *line = buffer;
	char *limit = buffer + used;
	while (line < limit) {
		char *end = memchr(line, '\n', (size_t)(limit - line));
		char *cursor = line;
		unsigned int value = 0;
		bool digits = false;
		bool value_fits = true;
		if (!end)
			end = limit;
		while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
			++cursor;
		while (cursor < end && *cursor >= '0' && *cursor <= '9') {
			digits = true;
			if (value > KER_TCP_REQUEST_REVOKE_MISC_MINOR_MAX / 10U ||
			    value * 10U + (unsigned int)(*cursor - '0') >
				KER_TCP_REQUEST_REVOKE_MISC_MINOR_MAX)
				value_fits = false;
			else
				value = value * 10U + (unsigned int)(*cursor - '0');
			++cursor;
		}
		while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
			++cursor;
		char *name = cursor;
		while (cursor < end && *cursor != ' ' && *cursor != '\t' && *cursor != '\r')
			++cursor;
		bool name_matches = (size_t)(cursor - name) ==
			strlen(KER_TCP_REQUEST_REVOKE_DEVICE_NAME) &&
			!memcmp(name, KER_TCP_REQUEST_REVOKE_DEVICE_NAME,
				strlen(KER_TCP_REQUEST_REVOKE_DEVICE_NAME));
		if (digits && value_fits && name_matches) {
			if (found)
				return -EPROTO;
			*minor = value;
			found = true;
		}
		line = end < limit ? end + 1 : limit;
	}
	return found ? 0 : -ENODEV;
}

int ker_native_tcp_request_revoke(
	const struct ker_tcp_request_revoke_request *request)
{
	struct ker_tcp_request_revoke_request copy;
	char path[80];
	unsigned int minor;
	long result;
	long fd;
	long removed;
	long closed;
	unsigned int sequence;

	if (!request)
		return -EINVAL;
	copy = *request;
	result = find_misc_minor(&minor);
	if (result < 0)
		return (int)result;
	sequence = atomic_fetch_add_explicit(&ker_tcp_request_revoke_sequence, 1,
		memory_order_relaxed);
	if (snprintf(path, sizeof(path), "/ker-native-tcp-request-revoke-%ld-%u",
		     lkl_sys_getpid(), sequence) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	result = lkl_sys_mknodat(LKL_AT_FDCWD, path,
		LKL_S_IFCHR | 0600, (minor & 0xffU) | (10U << 8) |
		((minor & ~0xffU) << 12));
	if (result < 0)
		return (int)result;
	fd = lkl_sys_open(path, LKL_O_RDWR | LKL_O_CLOEXEC, 0);
	removed = lkl_sys_unlinkat(LKL_AT_FDCWD, path, 0);
	if (fd < 0)
		return (int)fd;
	if (removed < 0) {
		(void)lkl_sys_close((unsigned int)fd);
		return (int)removed;
	}
	result = lkl_sys_ioctl((unsigned int)fd, KER_TCP_REQUEST_REVOKE,
		(unsigned long)&copy);
	closed = lkl_sys_close((unsigned int)fd);
	if (result < 0)
		return (int)result;
	return closed < 0 ? (int)closed : 0;
}
