// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "tcp-payload-snapshot.h"
#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_tcp_payload.h"
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KER_TCP_PAYLOAD_DEVICE_NAME "ker-tcp-payload"
#define KER_TCP_PAYLOAD_NODE "/ker-native-tcp-payload"
#define KER_TCP_PAYLOAD_PROC_MISC_MAX 8192U
#define KER_TCP_PAYLOAD_IOCTL_MAX_SOCKETS 4096U
#define KER_TCP_PAYLOAD_MISC_MINOR_MAX ((1U << 20) - 1)

_Static_assert(sizeof(struct ker_tcp_payload_request) == 32,
    "LKL private TCP payload ioctl ABI must be 32 bytes");

static int find_misc_minor(unsigned int *minor)
{
	char buffer[KER_TCP_PAYLOAD_PROC_MISC_MAX + 1];
	long fd = lkl_sys_open("/proc/misc", LKL_O_RDONLY | LKL_O_CLOEXEC, 0);
	size_t used = 0;
	long result;
	bool found = false;

	if (fd < 0)
		return (int)fd;
	for (;;) {
		result = lkl_sys_read((unsigned int)fd, buffer + used,
			KER_TCP_PAYLOAD_PROC_MISC_MAX - used);
		if (result < 0)
			break;
		if (!result) {
			result = 0;
			break;
		}
		used += (size_t)result;
		if (used == KER_TCP_PAYLOAD_PROC_MISC_MAX) {
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
			if (value > KER_TCP_PAYLOAD_MISC_MINOR_MAX / 10U || value * 10U +
			    (unsigned int)(*cursor - '0') > KER_TCP_PAYLOAD_MISC_MINOR_MAX)
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
			strlen(KER_TCP_PAYLOAD_DEVICE_NAME) &&
			!memcmp(name, KER_TCP_PAYLOAD_DEVICE_NAME,
				strlen(KER_TCP_PAYLOAD_DEVICE_NAME));
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

static int native_tcp_payload_snapshot_limit(uint32_t mark, uint32_t max_sockets,
	struct ker_socket_member_payload_snapshot *snapshot)
{
	if (!mark || !snapshot || !max_sockets || max_sockets > KER_TCP_PAYLOAD_IOCTL_MAX_SOCKETS)
		return -EINVAL;
	unsigned int minor = 0;
	int error = find_misc_minor(&minor);
	if (error)
		return error;
	long created = lkl_sys_mknodat(LKL_AT_FDCWD, KER_TCP_PAYLOAD_NODE,
		LKL_S_IFCHR | 0600, (minor & 0xffU) | (10U << 8) |
			((minor & ~0xffU) << 12));
	if (created < 0)
		return (int)created;
	long fd = lkl_sys_open(KER_TCP_PAYLOAD_NODE,
		LKL_O_RDWR | LKL_O_CLOEXEC, 0);
	long removed = lkl_sys_unlinkat(LKL_AT_FDCWD, KER_TCP_PAYLOAD_NODE, 0);
	if (fd < 0)
		return (int)fd;
	if (removed < 0) {
		(void)lkl_sys_close((unsigned int)fd);
		return (int)removed;
	}
	struct ker_tcp_payload_request request = {
		.version = KER_TCP_PAYLOAD_VERSION,
		.mark = mark,
		.max_sockets = max_sockets};
	long result = lkl_sys_ioctl((unsigned int)fd, KER_TCP_PAYLOAD_SNAPSHOT,
		(unsigned long)&request);
	long closed = lkl_sys_close((unsigned int)fd);
	if (result < 0)
		return (int)result;
	if (closed < 0)
		return (int)closed;
	if (request.version != KER_TCP_PAYLOAD_VERSION || request.mark != mark ||
	    request.max_sockets != max_sockets || request.reserved ||
	    request.sampled_sockets > max_sockets ||
	    (request.payload_bytes && !request.sampled_sockets))
		return -EPROTO;
	struct ker_socket_member_payload_snapshot completed = {
		.payload_bytes = request.payload_bytes,
		.sampled_sockets = request.sampled_sockets};
	*snapshot = completed;
	return 0;
}

int ker_native_tcp_payload_snapshot(uint32_t mark,
	struct ker_socket_member_payload_snapshot *snapshot)
{
	return native_tcp_payload_snapshot_limit(mark,
		KER_TCP_PAYLOAD_IOCTL_MAX_SOCKETS, snapshot);
}

#ifdef KER_MEMBER_CENSUS_TEST_RUNTIME
int ker_native_tcp_payload_snapshot_test_limit(uint32_t mark, uint32_t max_sockets,
	struct ker_socket_member_payload_snapshot *snapshot)
{
	return native_tcp_payload_snapshot_limit(mark, max_sockets, snapshot);
}
#endif
