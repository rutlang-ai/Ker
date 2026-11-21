#define _GNU_SOURCE
#include "tcp-event-snapshot.h"
#include "fd-table.h"
#include "lkl-overlay/arch/lkl/include/uapi/asm/ker_tcp_event.h"
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/stat.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <string.h>

#define KER_TCP_EVENT_DEVICE_NAME "ker-tcp-event"
#define KER_TCP_EVENT_NODE "/ker-native-tcp-event"
#define KER_TCP_EVENT_PROC_MISC_MAX 8192U
#define KER_TCP_EVENT_MINOR_MAX ((1U << 20) - 1)

_Static_assert(sizeof(struct ker_socket_event_snapshot) == 48,
    "public event snapshot must be 48 bytes");
_Static_assert(sizeof(struct ker_tcp_event_snapshot) == 48,
    "private event snapshot must be 48 bytes");
_Static_assert(sizeof(struct ker_tcp_event_query) == 64,
    "private event query must be 64 bytes");
_Static_assert(offsetof(struct ker_tcp_event_query, snapshot) == 16,
    "private event query snapshot offset must be 16");
_Static_assert(offsetof(struct ker_socket_event_snapshot, events) == 8,
    "public event snapshot events offset must be 8");
_Static_assert(offsetof(struct ker_socket_event_snapshot, family) == 16,
    "public event snapshot family offset must be 16");
_Static_assert(offsetof(struct ker_socket_event_snapshot, read_available) == 24,
    "public event snapshot read offset must be 24");
_Static_assert(offsetof(struct ker_socket_event_snapshot, write_accounting_space) == 32,
    "public event snapshot write offset must be 32");
_Static_assert(offsetof(struct ker_socket_event_snapshot, pending_hard_error) == 40,
    "public event snapshot error offset must be 40");
_Static_assert(offsetof(struct ker_socket_event_snapshot, flags) == 44,
    "public event snapshot flags offset must be 44");

static pthread_mutex_t query_lock = PTHREAD_MUTEX_INITIALIZER;

static int find_misc_minor(unsigned int *minor)
{
	char buffer[KER_TCP_EVENT_PROC_MISC_MAX + 1];
	long fd = lkl_sys_open("/proc/misc", LKL_O_RDONLY | LKL_O_CLOEXEC, 0);
	size_t used = 0;
	long result;
	bool found = false;

	if (fd < 0)
		return (int)fd;
	for (;;) {
		result = lkl_sys_read((unsigned int)fd, buffer + used,
			KER_TCP_EVENT_PROC_MISC_MAX - used);
		if (result < 0)
			break;
		if (!result) {
			result = 0;
			break;
		}
		used += (size_t)result;
		if (used == KER_TCP_EVENT_PROC_MISC_MAX) {
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
			if (value > KER_TCP_EVENT_MINOR_MAX / 10U ||
			    value * 10U + (unsigned int)(*cursor - '0') >
				KER_TCP_EVENT_MINOR_MAX)
				value_fits = false;
			else
				value = value * 10U + (unsigned int)(*cursor - '0');
			++cursor;
		}
		while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
			++cursor;
		char *name = cursor;
		while (cursor < end && *cursor != ' ' && *cursor != '\t' &&
		    *cursor != '\r')
			++cursor;
		bool matches = (size_t)(cursor - name) ==
			strlen(KER_TCP_EVENT_DEVICE_NAME) &&
			!memcmp(name, KER_TCP_EVENT_DEVICE_NAME,
				strlen(KER_TCP_EVENT_DEVICE_NAME));
		if (digits && value_fits && matches) {
			if (found)
				return -EPROTO;
			*minor = value;
			found = true;
		}
		line = end < limit ? end + 1 : limit;
	}
	return found ? 0 : -ENODEV;
}

int ker_native_socket_event_snapshot(int exported_fd,
	struct ker_socket_event_snapshot *snapshot)
{
	struct ker_tcp_event_query query = {
		.version = KER_TCP_EVENT_VERSION,
		.size = sizeof(query),
		.target_fd = -1,
	};
	struct ker_socket_event_snapshot completed;
	struct ker_fd *entry;
	unsigned int minor = 0;
	long created, fd, removed, result, closed;
	int error;

	if (!snapshot || exported_fd < 0)
		return -EINVAL;
	entry = ker_fd_get(exported_fd);
	if (!entry)
		return -EBADF;
	if (entry->kind != KER_FD_SOCKET) {
		ker_fd_put(entry);
		return -ENOTSOCK;
	}
	query.target_fd = entry->native;
	int lock_result = pthread_mutex_lock(&query_lock);
	if (lock_result) {
		ker_fd_put(entry);
		return -lock_result;
	}
	error = find_misc_minor(&minor);
	if (error)
		goto out_unlock;
	created = lkl_sys_mknodat(LKL_AT_FDCWD, KER_TCP_EVENT_NODE,
		LKL_S_IFCHR | 0600, (minor & 0xffU) | (10U << 8) |
			((minor & ~0xffU) << 12));
	if (created < 0) {
		error = (int)created;
		goto out_unlock;
	}
	fd = lkl_sys_open(KER_TCP_EVENT_NODE, LKL_O_RDWR | LKL_O_CLOEXEC, 0);
	removed = lkl_sys_unlinkat(LKL_AT_FDCWD, KER_TCP_EVENT_NODE, 0);
	if (fd < 0) {
		error = (int)fd;
		goto out_unlock;
	}
	if (removed < 0) {
		(void)lkl_sys_close((unsigned int)fd);
		(void)lkl_sys_unlinkat(LKL_AT_FDCWD, KER_TCP_EVENT_NODE, 0);
		error = (int)removed;
		goto out_unlock;
	}
	result = lkl_sys_ioctl((unsigned int)fd, KER_TCP_EVENT_SNAPSHOT,
		(unsigned long)&query);
	closed = lkl_sys_close((unsigned int)fd);
	if (result < 0) {
		error = (int)result;
		goto out_unlock;
	}
	if (closed < 0) {
		error = (int)closed;
		goto out_unlock;
	}
	const struct ker_tcp_event_snapshot *wire = &query.snapshot;
	if (wire->version != KER_TCP_EVENT_VERSION || wire->size != sizeof(*wire) ||
	    wire->reserved16 || (wire->validity & ~KER_TCP_EVENT_VALIDITY_MASK) ||
	    (wire->flags & ~KER_TCP_EVENT_FLAGS_MASK) || wire->pending_hard_error < 0 ||
	    wire->read_available < 0 || wire->write_accounting_space < 0 ||
	    !(wire->validity & KER_TCP_EVENT_HARD_ERROR_VALID) ||
	    !(wire->validity & KER_TCP_EVENT_READ_AVAILABLE_VALID) ||
	    (!!(wire->flags & KER_TCP_EVENT_LISTENER) ==
	     !!(wire->validity & KER_TCP_EVENT_WRITE_ACCOUNTING_VALID)) ||
	    (!(wire->validity & KER_TCP_EVENT_WRITE_ACCOUNTING_VALID) &&
	     wire->write_accounting_space) ||
	    (!(wire->validity & KER_TCP_EVENT_READ_AVAILABLE_VALID) &&
	     wire->read_available) ||
	    ((wire->flags & KER_TCP_EVENT_ERROR_QUEUE_ONLY) &&
	     wire->pending_hard_error) ||
	    (wire->family != AF_INET && wire->family != AF_INET6) ||
	    wire->type != SOCK_STREAM || wire->protocol != IPPROTO_TCP) {
		error = -EPROTO;
		goto out_unlock;
	}
	memcpy(&completed, wire, sizeof(completed));
	*snapshot = completed;
	error = 0;
out_unlock:
	(void)pthread_mutex_unlock(&query_lock);
	ker_fd_put(entry);
	return error;
}
