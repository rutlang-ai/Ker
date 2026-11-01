// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/inet_diag.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/sock_diag.h>
#include <linux/uaccess.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <uapi/asm/ker_tcp_request_revoke.h>

static_assert(sizeof(struct ker_tcp_request_revoke_request) == 72);

static bool ker_tcp_request_cookie_matches(struct sock *sk, const u32 cookie[2])
{
	u64 current_cookie = sock_gen_cookie(sk);

	return (u32)current_cookie == cookie[0] &&
		(u32)(current_cookie >> 32) == cookie[1];
}

static bool ker_tcp_request_tuple_matches(const struct sock *sk,
					 const struct ker_tcp_request_revoke_request *request)
{
	const struct inet_request_sock *ireq = inet_rsk(inet_reqsk(sk));

	if (request->family == AF_INET) {
		__be32 local, remote;

		memcpy(&local, request->local_address, sizeof(local));
		memcpy(&remote, request->remote_address, sizeof(remote));
		return ireq->ir_loc_addr == local && ireq->ir_rmt_addr == remote &&
			htons(ireq->ir_num) == request->local_port &&
			ireq->ir_rmt_port == request->remote_port &&
			ireq->ir_iif == request->ifindex;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (request->family == AF_INET6) {
		const struct in6_addr *local = (const struct in6_addr *)request->local_address;
		const struct in6_addr *remote = (const struct in6_addr *)request->remote_address;

		return ipv6_addr_equal(&ireq->ir_v6_loc_addr, local) &&
			ipv6_addr_equal(&ireq->ir_v6_rmt_addr, remote) &&
			htons(ireq->ir_num) == request->local_port &&
			ireq->ir_rmt_port == request->remote_port &&
			ireq->ir_iif == request->ifindex;
	}
#endif
	return false;
}

static int ker_tcp_request_validate(const struct sock *sk, struct net *net,
				    const struct ker_tcp_request_revoke_request *request)
{
	const struct request_sock *req;
	bool tcp_request;

	/* State must be checked before treating the common sock allocation as an
	 * inet_request_sock. A cookie can survive request-to-child promotion. */
	if (READ_ONCE(sk->sk_state) != TCP_NEW_SYN_RECV)
		return -ESTALE;
	req = inet_reqsk(sk);
	tcp_request = req->rsk_ops == &tcp_request_sock_ops;
#if IS_ENABLED(CONFIG_IPV6)
	tcp_request = tcp_request || req->rsk_ops == &tcp6_request_sock_ops;
#endif
	if (!tcp_request)
		return -ESTALE;
	if (sock_net(sk) != net || sk->sk_family != request->family)
		return -ESTALE;
	if (inet_rsk(req)->ir_mark != request->mark ||
	    !ker_tcp_request_tuple_matches(sk, request))
		return -ESTALE;
	return 0;
}

static long ker_tcp_request_revoke(unsigned long argument)
{
	struct ker_tcp_request_revoke_request request;
	struct inet_diag_req_v2 diag = {};
	struct sock *sk, *listener;
	struct request_sock *req;
	struct net *net;
	int error;
	bool removed;

	if (!ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.version != KER_TCP_REQUEST_REVOKE_VERSION || request.flags ||
	    !request.mark || !request.local_port || !request.remote_port ||
	    (request.family != AF_INET && request.family != AF_INET6) ||
	    (request.request_cookie[0] == INET_DIAG_NOCOOKIE &&
	     request.request_cookie[1] == INET_DIAG_NOCOOKIE) ||
	    (request.listener_cookie[0] == INET_DIAG_NOCOOKIE &&
	     request.listener_cookie[1] == INET_DIAG_NOCOOKIE))
		return -EINVAL;
	if (request.family == AF_INET &&
	    (memchr_inv(request.local_address + sizeof(__be32), 0, 12) ||
	     memchr_inv(request.remote_address + sizeof(__be32), 0, 12)))
		return -EINVAL;

	diag.sdiag_family = request.family;
	diag.sdiag_protocol = IPPROTO_TCP;
	diag.id.idiag_sport = request.local_port;
	diag.id.idiag_dport = request.remote_port;
	diag.id.idiag_if = request.ifindex;
	memcpy(diag.id.idiag_src, request.local_address, sizeof(request.local_address));
	memcpy(diag.id.idiag_dst, request.remote_address, sizeof(request.remote_address));
	memcpy(diag.id.idiag_cookie, request.request_cookie,
	       sizeof(request.request_cookie));

	net = current->nsproxy->net_ns;
	sk = inet_diag_find_one_icsk(net, &tcp_hashinfo, &diag);
	if (IS_ERR(sk))
		return PTR_ERR(sk);

	/* inet_diag_find_one_icsk returns a reference, including for fallback
	 * full sockets/listeners. Do not access request-only fields before state. */
	error = ker_tcp_request_validate(sk, net, &request);
	if (error)
		goto out_put_request;
	req = inet_reqsk(sk);
	listener = req->rsk_listener;
	if (!listener) {
		error = -ESTALE;
		goto out_put_request;
	}

	/* The request owns a listener reference. Serialize against listener close
	 * and validate the exact listener generation before calling the original
	 * helper. The timer callback does not acquire this socket lock; it races
	 * through ehash replacement, which the canonical drop reports as false. */
	lock_sock(listener);
	if (!sk_fullsock(listener) || READ_ONCE(listener->sk_state) != TCP_LISTEN ||
	    sock_net(listener) != net || listener->sk_protocol != IPPROTO_TCP ||
	    listener->sk_family != request.family ||
	    READ_ONCE(listener->sk_mark) != request.mark ||
	    !ker_tcp_request_cookie_matches(listener, request.listener_cookie) ||
	    READ_ONCE(sk->sk_state) != TCP_NEW_SYN_RECV ||
	    req->rsk_listener != listener ||
	    inet_rsk(req)->ir_mark != request.mark ||
	    !ker_tcp_request_tuple_matches(sk, &request)) {
		error = -ESTALE;
		goto out_unlock_listener;
	}

	/* This original Linux helper owns hash, timer, and queue reference changes.
	 * Its boolean is the only evidence that this exact request was revoked. */
	removed = inet_csk_reqsk_queue_drop(listener, req);
	error = removed ? 0 : -EAGAIN;

out_unlock_listener:
	release_sock(listener);
out_put_request:
	sock_gen_put(sk);
	return error;
}

static long ker_tcp_request_revoke_ioctl(struct file *file,
						unsigned int command,
						unsigned long argument)
{
	(void)file;
	if (command != KER_TCP_REQUEST_REVOKE)
		return -ENOTTY;
	return ker_tcp_request_revoke(argument);
}

static const struct file_operations ker_tcp_request_revoke_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ker_tcp_request_revoke_ioctl,
	.compat_ioctl = ker_tcp_request_revoke_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice ker_tcp_request_revoke_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ker-tcp-request-revoke",
	.fops = &ker_tcp_request_revoke_fops,
	.mode = 0600,
};

static int __init ker_tcp_request_revoke_init(void)
{
	return misc_register(&ker_tcp_request_revoke_device);
}

static void __exit ker_tcp_request_revoke_exit(void)
{
	misc_deregister(&ker_tcp_request_revoke_device);
}

module_init(ker_tcp_request_revoke_init);
module_exit(ker_tcp_request_revoke_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Private original Linux TCP request revocation adapter");
