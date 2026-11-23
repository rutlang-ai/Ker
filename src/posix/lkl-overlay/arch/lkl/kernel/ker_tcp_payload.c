// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>
#include <net/inet_hashtables.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <asm/ker_tcp_payload_accounting.h>
#include <uapi/asm/ker_tcp_payload.h>

#define KER_TCP_PAYLOAD_MAX_SOCKETS 4096U
#define KER_TCP_PAYLOAD_MAX_BUCKETS 262144U
#define KER_TCP_PAYLOAD_MAX_BUCKET_NODES 1024U
#define KER_TCP_PAYLOAD_MAX_VISITED_NODES 65536U

static int ker_tcp_payload_socket(struct sock *sk, struct net *net, u32 mark)
{
	return sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP &&
		(sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
		READ_ONCE(sk->sk_state) != TCP_LISTEN && sock_net(sk) == net &&
		READ_ONCE(sk->sk_mark) == mark;
}

static int ker_tcp_payload_skb(struct sk_buff *skb, u32 snd_una, u64 *bytes)
{
	u64 pending = 0;
	int error;

	error = ker_tcp_payload_pending(TCP_SKB_CB(skb)->seq,
		TCP_SKB_CB(skb)->end_seq, snd_una, skb->len,
		TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN,
		TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN, &pending);
	if (error)
		return -EPROTO;
	if (ker_tcp_payload_accumulate(bytes, pending))
		return -EOVERFLOW;
	return 0;
}

static int ker_tcp_payload_queue_skb(struct sk_buff *skb, u32 snd_una,
	u64 *bytes, u32 *total_nodes, u32 *socket_nodes)
{
	if (ker_tcp_payload_queue_node(total_nodes, socket_nodes))
		return -EAGAIN;
	return ker_tcp_payload_skb(skb, snd_una, bytes);
}

static int ker_tcp_payload_socket_locked(struct sock *sk, struct net *net,
	u32 mark, u64 *bytes, u32 *total_queue_nodes)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	struct rb_node *node;
	u32 snd_una;
	u32 socket_queue_nodes = 0;
	int error = 0;

	lock_sock(sk);
	if (!sk_fullsock(sk) || sock_net(sk) != net || READ_ONCE(sk->sk_mark) != mark ||
	    sk->sk_protocol != IPPROTO_TCP ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    sk->sk_state == TCP_LISTEN) {
		error = -EAGAIN;
		goto out;
	}
	/* `snd_una` and both disjoint queues are read under this socket lock.
	 * `skb->len` is logical payload length (including non-linear/GSO data),
	 * while the sequence interval includes SYN/FIN sequence space. */
	snd_una = tp->snd_una;
	skb_queue_walk(&sk->sk_write_queue, skb) {
		error = ker_tcp_payload_queue_skb(skb, snd_una, bytes,
			total_queue_nodes, &socket_queue_nodes);
		if (error)
			goto out;
	}
	for (node = rb_first(&sk->tcp_rtx_queue); node; node = rb_next(node)) {
		skb = rb_entry(node, struct sk_buff, rbnode);
		error = ker_tcp_payload_queue_skb(skb, snd_una, bytes,
			total_queue_nodes, &socket_queue_nodes);
		if (error)
			goto out;
	}
out:
	release_sock(sk);
	return error;
}

static int ker_tcp_payload_compare_socket(const void *left, const void *right)
{
	unsigned long a = (unsigned long)*(struct sock * const *)left;
	unsigned long b = (unsigned long)*(struct sock * const *)right;

	return a < b ? -1 : a > b;
}

static long ker_tcp_payload_snapshot(unsigned long argument)
{
	struct ker_tcp_payload_request request;
	struct sock **sockets;
	struct net *net;
	struct inet_hashinfo *hashinfo;
	u64 payload_bytes = 0;
	u32 selected = 0;
	u32 visited = 0;
	u32 visited_queue_nodes = 0;
	int error = 0;
	unsigned int bucket_index;

	if (!ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.version != KER_TCP_PAYLOAD_VERSION || !request.mark ||
	    !request.max_sockets || request.max_sockets > KER_TCP_PAYLOAD_MAX_SOCKETS ||
	    request.reserved)
		return -EINVAL;
	request.payload_bytes = 0;
	request.sampled_sockets = 0;
	sockets = kvcalloc(request.max_sockets, sizeof(*sockets), GFP_KERNEL);
	if (!sockets)
		return -ENOMEM;
	net = get_net(current->nsproxy->net_ns);
	hashinfo = net->ipv4.tcp_death_row.hashinfo;
	/* LKL's UP spinlock type is intentionally zero-sized. In that build,
	 * inet_ehash_locks_alloc() leaves ehash_locks NULL and the canonical
	 * ehash lock helpers are no-ops. */
	if (!hashinfo || !hashinfo->ehash ||
	    (sizeof(spinlock_t) && !hashinfo->ehash_locks) ||
	    hashinfo->ehash_mask >= KER_TCP_PAYLOAD_MAX_BUCKETS) {
		error = -EAGAIN;
		goto out;
	}

	/* Socket hash membership pins the pointer while this bucket lock is held.
	 * Take one explicit reference, then release the lock before any sleeping
	 * socket lock or queue walk. The nulls chain is stable under its ehash lock. */
	for (bucket_index = 0; bucket_index <= hashinfo->ehash_mask; ++bucket_index) {
		struct inet_ehash_bucket *bucket = inet_ehash_bucket(hashinfo, bucket_index);
		spinlock_t *lock = inet_ehash_lockp(hashinfo, bucket_index);
		struct sock *sk;
		struct hlist_nulls_node *node;
		u32 bucket_nodes = 0;

		spin_lock_bh(lock);
		sk_nulls_for_each(sk, node, &bucket->chain) {
			if (++bucket_nodes > KER_TCP_PAYLOAD_MAX_BUCKET_NODES ||
			    ++visited > KER_TCP_PAYLOAD_MAX_VISITED_NODES) {
				error = -EAGAIN;
				break;
			}
			if (!ker_tcp_payload_socket(sk, net, request.mark))
				continue;
			if (selected == request.max_sockets) {
				error = -EOVERFLOW;
				break;
			}
			if (!refcount_inc_not_zero(&sk->sk_refcnt)) {
				error = -EAGAIN;
				break;
			}
			sockets[selected++] = sk;
		}
		spin_unlock_bh(lock);
		if (error)
			goto out;
		cond_resched();
	}

	/* A privileged caller may concurrently rehash a full socket while this
	 * sequential scan advances between buckets. Never count one pointer twice. */
	sort(sockets, selected, sizeof(*sockets), ker_tcp_payload_compare_socket, NULL);
	for (bucket_index = 1; bucket_index < selected; ++bucket_index) {
		if (sockets[bucket_index - 1] == sockets[bucket_index]) {
			error = -EAGAIN;
			goto out;
		}
	}

	for (bucket_index = 0; bucket_index < selected; ++bucket_index) {
		error = ker_tcp_payload_socket_locked(sockets[bucket_index], net,
			request.mark, &payload_bytes, &visited_queue_nodes);
		if (error)
			goto out;
	}
	request.payload_bytes = payload_bytes;
	request.sampled_sockets = selected;
	if (copy_to_user((void __user *)argument, &request, sizeof(request)))
		error = -EFAULT;
out:
	while (selected)
		sock_put(sockets[--selected]);
	put_net(net);
	kvfree(sockets);
	return error;
}

static long ker_tcp_payload_ioctl(struct file *file, unsigned int command,
	unsigned long argument)
{
	(void)file;
	if (command != KER_TCP_PAYLOAD_SNAPSHOT)
		return -ENOTTY;
	return ker_tcp_payload_snapshot(argument);
}

static const struct file_operations ker_tcp_payload_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ker_tcp_payload_ioctl,
	.compat_ioctl = ker_tcp_payload_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice ker_tcp_payload_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ker-tcp-payload",
	.fops = &ker_tcp_payload_fops,
	.mode = 0600,
};

static int __init ker_tcp_payload_init(void)
{
	return misc_register(&ker_tcp_payload_device);
}

static void __exit ker_tcp_payload_exit(void)
{
	misc_deregister(&ker_tcp_payload_device);
}

module_init(ker_tcp_payload_init);
module_exit(ker_tcp_payload_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded original Linux TCP queued-payload snapshot for Ker");
