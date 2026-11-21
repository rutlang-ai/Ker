// SPDX-License-Identifier: GPL-2.0-only
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/sockios.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <uapi/asm/ker_tcp_event.h>
#include <uapi/linux/eventpoll.h>

static_assert(sizeof(struct ker_tcp_event_snapshot) == 48);
static_assert(offsetof(struct ker_tcp_event_snapshot, events) == 8);
static_assert(offsetof(struct ker_tcp_event_snapshot, family) == 16);
static_assert(offsetof(struct ker_tcp_event_snapshot, read_available) == 24);
static_assert(offsetof(struct ker_tcp_event_snapshot, write_accounting_space) == 32);
static_assert(offsetof(struct ker_tcp_event_snapshot, pending_hard_error) == 40);
static_assert(offsetof(struct ker_tcp_event_snapshot, flags) == 44);
static_assert(sizeof(struct ker_tcp_event_query) == 64);
static_assert(offsetof(struct ker_tcp_event_query, snapshot) == 16);

static long ker_tcp_event_read_snapshot(unsigned long argument)
{
	struct ker_tcp_event_query query;
	struct ker_tcp_event_snapshot snapshot = {0};
	struct file *file;
	struct socket *sock;
	struct sock *sk;
	int inq;
	int error;
	bool listener;
	bool error_queue;
	int state_before;
	const __poll_t allowed_events = EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR |
		EPOLLHUP | EPOLLRDNORM | EPOLLWRNORM | EPOLLRDHUP;

	if (copy_from_user(&query, (void __user *)argument, sizeof(query)))
		return -EFAULT;
	if (query.version != KER_TCP_EVENT_VERSION ||
	    query.size != sizeof(query) || query.target_fd < 0 || query.reserved ||
	    memchr_inv(&query.snapshot, 0, sizeof(query.snapshot)))
		return -EINVAL;

	file = fget(query.target_fd);
	if (!file)
		return -EBADF;
	sock = sock_from_file(file);
	if (!sock || !sock->sk) {
		error = -ENOTSOCK;
		goto out_file;
	}
	sk = sock->sk;
	if ((sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sock->type != SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP ||
	    !sk_fullsock(sk)) {
		error = -EOPNOTSUPP;
		goto out_file;
	}

	lock_sock(sk);
	state_before = READ_ONCE(sk->sk_state);
	release_sock(sk);
	__poll_t events = tcp_poll(file, sock, NULL);
	if (events & ~allowed_events) {
		error = -EPROTO;
		goto out_file;
	}
	lock_sock(sk);
	if (READ_ONCE(sk->sk_state) != state_before) {
		release_sock(sk);
		error = -EAGAIN;
		goto out_file;
	}
	listener = state_before == TCP_LISTEN;
	snapshot.version = KER_TCP_EVENT_VERSION;
	snapshot.size = sizeof(snapshot);
	snapshot.events = events;
	snapshot.family = sk->sk_family;
	snapshot.type = sock->type;
	snapshot.protocol = sk->sk_protocol;
	snapshot.validity = KER_TCP_EVENT_HARD_ERROR_VALID;
	/* Preserve the original Linux receive/send shutdown state as distinct
	 * metadata. tcp_poll's EPOLLRDHUP alone does not imply local write EOF. */
	unsigned char shutdown_state = READ_ONCE(sk->sk_shutdown);
	if (shutdown_state & RCV_SHUTDOWN)
		snapshot.flags |= KER_TCP_EVENT_READ_SHUTDOWN;
	if (shutdown_state & SEND_SHUTDOWN)
		snapshot.flags |= KER_TCP_EVENT_WRITE_SHUTDOWN;
	if (listener) {
		/* Matches the accept-ready child count used by original Linux
		 * listener metadata; FIONREAD/SIOCINQ is invalid for LISTEN.
		 * The queue lock is also used by reqsk_queue_remove/add around
		 * sk_acceptq_removed/added. */
		struct request_sock_queue *queue =
			&inet_csk(sk)->icsk_accept_queue;
		spin_lock_bh(&queue->rskq_lock);
		snapshot.read_available = READ_ONCE(sk->sk_ack_backlog);
		spin_unlock_bh(&queue->rskq_lock);
		snapshot.validity |= KER_TCP_EVENT_READ_AVAILABLE_VALID;
		snapshot.flags |= KER_TCP_EVENT_LISTENER;
	} else {
		/* tcp_ioctl(SIOCINQ) uses this original helper under the socket
		 * lock. Keep the count and wmem accounting in the same lock hold. */
		inq = tcp_inq(sk);
		if (inq < 0) {
			release_sock(sk);
			error = -EOVERFLOW;
			goto out_file;
		}
		snapshot.read_available = inq;
		snapshot.write_accounting_space = max_t(int,
			sk_stream_wspace(sk), 0);
		snapshot.validity |= KER_TCP_EVENT_READ_AVAILABLE_VALID |
			KER_TCP_EVENT_WRITE_ACCOUNTING_VALID;
	}
	/* tcp_poll is intentionally the original unlocked Linux helper. All
	 * value/accounting/error fields are sampled together while the socket
	 * lock is held; readiness is its own native poll-time observation. */
	smp_rmb();
	snapshot.pending_hard_error = READ_ONCE(sk->sk_err);
	error_queue = !skb_queue_empty_lockless(&sk->sk_error_queue);
	if (!snapshot.pending_hard_error && error_queue)
		snapshot.flags |= KER_TCP_EVENT_ERROR_QUEUE_ONLY;
	release_sock(sk);

	query.snapshot = snapshot;
	error = copy_to_user((void __user *)argument, &query, sizeof(query)) ?
		-EFAULT : 0;
out_file:
	fput(file);
	return error;
}

static long ker_tcp_event_ioctl(struct file *file, unsigned int command,
	unsigned long argument)
{
	(void)file;
	if (command != KER_TCP_EVENT_SNAPSHOT)
		return -ENOTTY;
	return ker_tcp_event_read_snapshot(argument);
}

static const struct file_operations ker_tcp_event_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ker_tcp_event_ioctl,
	.compat_ioctl = ker_tcp_event_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice ker_tcp_event_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ker-tcp-event",
	.fops = &ker_tcp_event_fops,
	.mode = 0600,
};

static int __init ker_tcp_event_init(void)
{
	return misc_register(&ker_tcp_event_device);
}

static void __exit ker_tcp_event_exit(void)
{
	misc_deregister(&ker_tcp_event_device);
}

module_init(ker_tcp_event_init);
module_exit(ker_tcp_event_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Nonconsuming original Linux TCP event metadata for Ker");
