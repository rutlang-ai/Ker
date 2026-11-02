// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/limits.h>
#include <linux/ktime.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/nsproxy.h>
#include <linux/sock_diag.h>
#include <linux/user_namespace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <uapi/asm/ker_ff_admission_queue.h>

static_assert(sizeof(struct ker_ff_admission_queue_control) == 32);

static u64 ker_ff_admission_state;
static atomic64_t ker_ff_admission_next_lease = ATOMIC64_INIT(0);
static u64 ker_ff_admission_lease;
static DEFINE_MUTEX(ker_ff_admission_control_lock);
static u32 ker_ff_ingress_active;
static u32 ker_ff_ingress_quarantined;
static __be32 ker_ff_ingress_address;
static __be16 ker_ff_ingress_port;
static u64 ker_ff_ingress_lease;
static u64 ker_ff_ingress_deadline_ns;
static struct sock *ker_ff_ingress_listener;
static u64 ker_ff_ingress_listener_cookie;
static u32 ker_ff_ingress_listener_mark;
static atomic64_t ker_ff_ingress_next_lease = ATOMIC64_INIT(0);
static atomic64_t ker_ff_ingress_attempt_count = ATOMIC64_INIT(0);
static atomic64_t ker_ff_ingress_expired_count = ATOMIC64_INIT(0);
static atomic64_t ker_ff_ingress_inventory_error_count = ATOMIC64_INIT(0);
static const struct nf_hook_ops ker_ff_ingress_ops;

#if defined(CONFIG_SMP) || !defined(CONFIG_PREEMPT_NONE) || \
	!defined(CONFIG_TINY_RCU) || defined(CONFIG_PREEMPT) || \
	defined(CONFIG_PREEMPT_RT) || defined(CONFIG_PREEMPT_DYNAMIC) || \
	defined(CONFIG_MODULES) || defined(CONFIG_NF_TABLES) || \
	defined(CONFIG_NETFILTER_XTABLES) || defined(CONFIG_IP_NF_IPTABLES) || \
	defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_IP_VS) || \
	defined(CONFIG_BPF_SYSCALL)
#define KER_FF_INGRESS_PROFILE_SUPPORTED 0
#else
#define KER_FF_INGRESS_PROFILE_SUPPORTED 1
#endif

static_assert(sizeof(struct ker_ff_ingress_freeze_control) == 80);
#define KER_FF_INGRESS_LEASE_NS (30ULL * NSEC_PER_SEC)

/* This profile deliberately supports exactly this one LOCAL_IN hook.  The
 * pinned UP/non-preemptible build has no runtime module/iptables/nftables hook
 * registrants; rechecking the immutable list detects any unexpected change. */
static bool ker_ff_ingress_hook_inventory_valid(void)
{
	struct nf_hook_entries *entries;
	struct nf_hook_ops **ops;
	bool valid = false;

	rcu_read_lock();
	entries = rcu_dereference(init_net.nf.hooks_ipv4[NF_INET_LOCAL_IN]);
	if (entries && entries->num_hook_entries == 1) {
		ops = nf_hook_entries_get_hook_ops(entries);
		valid = ops[0] == &ker_ff_ingress_ops;
	}
	rcu_read_unlock();
	return valid;
}

static bool ker_ff_ingress_listener_valid(void)
{
	struct sock *sk = READ_ONCE(ker_ff_ingress_listener);
	struct inet_sock *inet;

	if (!sk || sk->sk_state != TCP_LISTEN ||
	    sk->sk_mark != READ_ONCE(ker_ff_ingress_listener_mark) ||
	    sock_gen_cookie(sk) != READ_ONCE(ker_ff_ingress_listener_cookie))
		return false;
	inet = inet_sk(sk);
	return READ_ONCE(inet->inet_rcv_saddr) ==
		READ_ONCE(ker_ff_ingress_address) &&
		htons(READ_ONCE(inet->inet_num)) == READ_ONCE(ker_ff_ingress_port);
}

static unsigned int ker_ff_admission_local_out(void *priv, struct sk_buff *skb,
						      const struct nf_hook_state *state)
{
	struct iphdr iph;
	struct tcphdr th;
	int network_offset = skb_network_offset(skb);
	unsigned int offset;
	u64 admission = READ_ONCE(ker_ff_admission_state);

	(void)priv;
	(void)state;
	if (!(admission >> 32) || skb->mark != (u32)admission ||
	    skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (network_offset < 0 || skb_copy_bits(skb, network_offset, &iph,
					       sizeof(iph)))
		return NF_DROP;
	if (iph.version != 4 || iph.ihl < 5 || iph.protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	offset = iph.ihl * 4;
	if (ntohs(iph.tot_len) < offset + sizeof(th) ||
	    skb_copy_bits(skb, network_offset + offset, &th, sizeof(th)))
		return NF_DROP;
	if (th.doff < sizeof(th) / 4 || ntohs(iph.tot_len) < offset + th.doff * 4)
		return NF_DROP;
	if (!th.syn || !th.ack || th.rst)
		return NF_ACCEPT;
	return NF_QUEUE_NR(KER_FF_ADMISSION_QUEUE_NUMBER);
}

static const struct nf_hook_ops ker_ff_admission_ops = {
	.hook = ker_ff_admission_local_out,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST,
};

static unsigned int ker_ff_ingress_local_in(void *priv, struct sk_buff *skb,
						    const struct nf_hook_state *state)
{
	struct iphdr iph;
	struct tcphdr th;
	int network_offset;
	unsigned int ip_header_length;
	unsigned int tcp_header_length;

	(void)priv;
	if ((!READ_ONCE(ker_ff_ingress_active) &&
	     !READ_ONCE(ker_ff_ingress_quarantined)) || state->net != &init_net ||
	    skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	network_offset = skb_network_offset(skb);
	if (network_offset < 0 || skb_copy_bits(skb, network_offset, &iph,
					       sizeof(iph)))
		return NF_ACCEPT;
	if (iph.version != 4 || iph.ihl < 5 || iph.protocol != IPPROTO_TCP ||
	    iph.daddr != READ_ONCE(ker_ff_ingress_address))
		return NF_ACCEPT;
	ip_header_length = iph.ihl * 4;
	if (ntohs(iph.tot_len) < ip_header_length + sizeof(th) ||
	    skb_copy_bits(skb, network_offset + ip_header_length, &th,
			   sizeof(th)))
		return NF_ACCEPT;
	if (th.doff < sizeof(th) / 4 || th.doff > 15)
		return NF_ACCEPT;
	tcp_header_length = th.doff * 4;
	if (ntohs(iph.tot_len) < ip_header_length + tcp_header_length ||
	    th.dest != READ_ONCE(ker_ff_ingress_port))
		return NF_ACCEPT;

	/* Hold only an initial SYN for this exact listener tuple. Malformed and
	 * unrelated traffic continues through the original Linux input path. */
	if (!th.syn || th.ack || th.rst || th.fin)
		return NF_ACCEPT;
	if (READ_ONCE(ker_ff_ingress_quarantined))
		return NF_DROP;
	atomic64_inc(&ker_ff_ingress_attempt_count);
	if (ktime_get_ns() >= READ_ONCE(ker_ff_ingress_deadline_ns)) {
		atomic64_inc(&ker_ff_ingress_expired_count);
		return NF_DROP;
	}
	if (!ker_ff_ingress_hook_inventory_valid()) {
		atomic64_inc(&ker_ff_ingress_inventory_error_count);
		return NF_DROP;
	}
	return NF_QUEUE_NR(KER_FF_INGRESS_FREEZE_QUEUE_NUMBER);
}

static const struct nf_hook_ops ker_ff_ingress_ops = {
	.hook = ker_ff_ingress_local_in,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	/* The exact guarded artifact has no later enabled LOCAL_IN hooks. */
	.priority = INT_MAX,
};

static long ker_ff_ingress_freeze_set(unsigned long argument)
{
	struct ker_ff_ingress_freeze_control control;
	struct socket *socket;
	struct sock *sk;
	struct inet_sock *inet;
	__be32 local_address;
	__be16 local_port;
	u64 cookie;
	int error = 0;

	if (current->nsproxy->net_ns != &init_net ||
	    !ns_capable(&init_user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (copy_from_user(&control, (void __user *)argument, sizeof(control)))
		return -EFAULT;
	if (control.version != KER_FF_ADMISSION_QUEUE_VERSION ||
	    control.reserved16 || control.reserved32 || control.attempt_count ||
	    control.expired_count || control.inventory_error_count)
		return -EINVAL;

	mutex_lock(&ker_ff_admission_control_lock);
	if (!KER_FF_INGRESS_PROFILE_SUPPORTED) {
		error = -EOPNOTSUPP;
		goto out;
	}
	if (control.operation == KER_FF_INGRESS_FREEZE_ARM) {
		if (control.listener_fd < 0 || !control.expected_mark ||
		    control.expected_mark > INT_MAX || !control.expected_cookie ||
		    control.lease || control.deadline_ns || control.local_address ||
		    control.local_port) {
			error = -EINVAL;
			goto out;
		}
		if (READ_ONCE(ker_ff_ingress_lease)) {
			error = -EBUSY;
			goto out;
		}
		if (!ker_ff_ingress_hook_inventory_valid()) {
			error = -EOPNOTSUPP;
			goto out;
		}
		socket = sockfd_lookup(control.listener_fd, &error);
		if (!socket)
			goto out;
		sk = socket->sk;
		if (!sk || socket->type != SOCK_STREAM ||
		    sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP ||
		    sk->sk_state != TCP_LISTEN ||
		    sk->sk_mark != control.expected_mark) {
			error = -EOPNOTSUPP;
			goto put_socket;
		}
		inet = inet_sk(sk);
		local_address = READ_ONCE(inet->inet_rcv_saddr);
		local_port = htons(READ_ONCE(inet->inet_num));
		cookie = sock_gen_cookie(sk);
		if (!local_address || !local_port ||
		    cookie != control.expected_cookie) {
			error = -ESTALE;
			goto put_socket;
		}
		if (atomic64_read(&ker_ff_ingress_next_lease) == U64_MAX) {
			error = -EOVERFLOW;
			goto put_socket;
		}
		control.lease = atomic64_inc_return(&ker_ff_ingress_next_lease);
		control.deadline_ns = ktime_get_ns() + KER_FF_INGRESS_LEASE_NS;
		control.local_address = local_address;
		control.local_port = local_port;
		if (copy_to_user((void __user *)argument, &control,
				 sizeof(control))) {
			error = -EFAULT;
			goto put_socket;
		}
		WRITE_ONCE(ker_ff_ingress_address, local_address);
		WRITE_ONCE(ker_ff_ingress_port, local_port);
		WRITE_ONCE(ker_ff_ingress_lease, control.lease);
		WRITE_ONCE(ker_ff_ingress_deadline_ns, control.deadline_ns);
		sock_hold(sk);
		WRITE_ONCE(ker_ff_ingress_listener, sk);
		WRITE_ONCE(ker_ff_ingress_listener_cookie, cookie);
		WRITE_ONCE(ker_ff_ingress_listener_mark, control.expected_mark);
		atomic64_set(&ker_ff_ingress_attempt_count, 0);
		atomic64_set(&ker_ff_ingress_expired_count, 0);
		atomic64_set(&ker_ff_ingress_inventory_error_count, 0);
		WRITE_ONCE(ker_ff_ingress_active, 1);
put_socket:
		sockfd_put(socket);
	} else if (control.operation == KER_FF_INGRESS_FREEZE_CHECK) {
		if (control.listener_fd || control.expected_mark ||
		    control.expected_cookie || !control.lease ||
		    control.deadline_ns || control.local_address || control.local_port) {
			error = -EINVAL;
			goto out;
		}
		if (READ_ONCE(ker_ff_ingress_quarantined)) {
			error = -ECANCELED;
			goto out;
		}
		if (control.lease != READ_ONCE(ker_ff_ingress_lease) ||
		    !control.lease) {
			error = -ESTALE;
			goto out;
		}
		control.attempt_count = atomic64_read(&ker_ff_ingress_attempt_count);
		control.expired_count = atomic64_read(&ker_ff_ingress_expired_count);
		control.inventory_error_count =
			atomic64_read(&ker_ff_ingress_inventory_error_count);
		if (!ker_ff_ingress_hook_inventory_valid())
			error = -EOPNOTSUPP;
		else if (!ker_ff_ingress_listener_valid())
			error = -ESTALE;
		else if (ktime_get_ns() >= READ_ONCE(ker_ff_ingress_deadline_ns))
			error = -ETIMEDOUT;
		else if (copy_to_user((void __user *)argument, &control,
				      sizeof(control)))
			error = -EFAULT;
	} else if (control.operation == KER_FF_INGRESS_FREEZE_DISARM) {
		if (control.listener_fd || control.expected_mark ||
		    control.expected_cookie || !control.lease ||
		    control.deadline_ns || control.local_address || control.local_port) {
			error = -EINVAL;
			goto out;
		}
		if (READ_ONCE(ker_ff_ingress_quarantined)) {
			error = -ECANCELED;
			goto out;
		}
		if (!READ_ONCE(ker_ff_ingress_active) ||
		    control.lease != READ_ONCE(ker_ff_ingress_lease)) {
			error = -ESTALE;
			goto out;
		}
		if (!ker_ff_ingress_hook_inventory_valid()) {
			error = -EOPNOTSUPP;
			goto out;
		}
		if (!ker_ff_ingress_listener_valid()) {
			error = -ESTALE;
			goto out;
		}
		if (ktime_get_ns() >= READ_ONCE(ker_ff_ingress_deadline_ns)) {
			error = -ETIMEDOUT;
			goto out;
		}
		WRITE_ONCE(ker_ff_ingress_active, 0);
		control.attempt_count = atomic64_read(&ker_ff_ingress_attempt_count);
		control.expired_count = atomic64_read(&ker_ff_ingress_expired_count);
		control.inventory_error_count =
			atomic64_read(&ker_ff_ingress_inventory_error_count);
		if (copy_to_user((void __user *)argument, &control,
				 sizeof(control)))
			error = -EFAULT;
	} else if (control.operation == KER_FF_INGRESS_FREEZE_RELEASE) {
		if (control.listener_fd || control.expected_mark ||
		    control.expected_cookie || !control.lease ||
		    control.deadline_ns || control.local_address || control.local_port) {
			error = -EINVAL;
			goto out;
		}
		if (READ_ONCE(ker_ff_ingress_quarantined)) {
			error = -ECANCELED;
			goto out;
		}
		if (READ_ONCE(ker_ff_ingress_active) ||
		    control.lease != READ_ONCE(ker_ff_ingress_lease)) {
			error = -ESTALE;
			goto out;
		}
		if (!ker_ff_ingress_hook_inventory_valid()) {
			error = -EOPNOTSUPP;
			goto out;
		}
		WRITE_ONCE(ker_ff_ingress_address, 0);
		WRITE_ONCE(ker_ff_ingress_port, 0);
		WRITE_ONCE(ker_ff_ingress_lease, 0);
		WRITE_ONCE(ker_ff_ingress_deadline_ns, 0);
		sk = READ_ONCE(ker_ff_ingress_listener);
		WRITE_ONCE(ker_ff_ingress_listener, NULL);
		WRITE_ONCE(ker_ff_ingress_listener_cookie, 0);
		WRITE_ONCE(ker_ff_ingress_listener_mark, 0);
		sock_put(sk);
	} else if (control.operation == KER_FF_INGRESS_FREEZE_QUARANTINE) {
		if (control.listener_fd || control.expected_mark ||
		    control.expected_cookie || !control.lease ||
		    control.deadline_ns || control.local_address || control.local_port) {
			error = -EINVAL;
			goto out;
		}
		if (!READ_ONCE(ker_ff_ingress_lease) ||
		    control.lease != READ_ONCE(ker_ff_ingress_lease)) {
			error = -ESTALE;
			goto out;
		}
		WRITE_ONCE(ker_ff_ingress_active, 0);
		WRITE_ONCE(ker_ff_ingress_quarantined, 1);
	} else {
		error = -EINVAL;
	}
out:
	mutex_unlock(&ker_ff_admission_control_lock);
	return error;
}

static long ker_ff_admission_set(unsigned long argument)
{
	struct ker_ff_admission_queue_control control;
	int error = 0;

	if (current->nsproxy->net_ns != &init_net ||
	    !ns_capable(&init_user_ns, CAP_NET_ADMIN))
		return -EPERM;
	if (copy_from_user(&control, (void __user *)argument, sizeof(control)))
		return -EFAULT;
	u64 previous = READ_ONCE(ker_ff_admission_state);
	if (control.version != KER_FF_ADMISSION_QUEUE_VERSION || control.flags ||
	    control.enabled > 1 || (control.enabled && !control.mark) ||
	    (!control.enabled && control.mark) || control.reserved ||
	    (control.enabled && (control.lease || control.expected_mark)))
		return -EINVAL;
	mutex_lock(&ker_ff_admission_control_lock);
	previous = READ_ONCE(ker_ff_admission_state);
	if (control.enabled) {
		if (previous) {
			error = -EBUSY;
			goto out;
		}
		control.lease = atomic64_inc_return(&ker_ff_admission_next_lease);
		if (!control.lease)
			control.lease = atomic64_inc_return(&ker_ff_admission_next_lease);
		if (copy_to_user((void __user *)argument, &control, sizeof(control))) {
			error = -EFAULT;
			goto out;
		}
		ker_ff_admission_lease = control.lease;
		WRITE_ONCE(ker_ff_admission_state, (1ULL << 32) | control.mark);
	} else {
		if (!previous || (u32)previous != control.expected_mark ||
		    control.lease != ker_ff_admission_lease) {
			error = -ESTALE;
			goto out;
		}
		WRITE_ONCE(ker_ff_admission_state, 0);
		ker_ff_admission_lease = 0;
	}
out:
	mutex_unlock(&ker_ff_admission_control_lock);
	return error;
}

static long ker_ff_admission_ioctl(struct file *file, unsigned int command,
				  unsigned long argument)
{
	(void)file;
	if (command == KER_FF_ADMISSION_QUEUE_SET)
		return ker_ff_admission_set(argument);
	if (command == KER_FF_INGRESS_FREEZE_SET)
		return ker_ff_ingress_freeze_set(argument);
	return -ENOTTY;
}

static const struct file_operations ker_ff_admission_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ker_ff_admission_ioctl,
	.compat_ioctl = ker_ff_admission_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice ker_ff_admission_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ker-ff-admission-queue",
	.fops = &ker_ff_admission_fops,
	.mode = 0600,
};

static int __init ker_ff_admission_init(void)
{
	int error = nf_register_net_hook(&init_net, &ker_ff_admission_ops);

	if (error)
		return error;
	error = nf_register_net_hook(&init_net, &ker_ff_ingress_ops);
	if (error) {
		nf_unregister_net_hook(&init_net, &ker_ff_admission_ops);
		return error;
	}
	error = misc_register(&ker_ff_admission_device);
	if (error) {
		nf_unregister_net_hook(&init_net, &ker_ff_ingress_ops);
		nf_unregister_net_hook(&init_net, &ker_ff_admission_ops);
	}
	return error;
}

static void __exit ker_ff_admission_exit(void)
{
	struct sock *ingress_listener = READ_ONCE(ker_ff_ingress_listener);
	WRITE_ONCE(ker_ff_admission_state, 0);
	ker_ff_admission_lease = 0;
	WRITE_ONCE(ker_ff_ingress_active, 0);
	WRITE_ONCE(ker_ff_ingress_quarantined, 0);
	WRITE_ONCE(ker_ff_ingress_address, 0);
	WRITE_ONCE(ker_ff_ingress_port, 0);
	WRITE_ONCE(ker_ff_ingress_lease, 0);
	WRITE_ONCE(ker_ff_ingress_deadline_ns, 0);
	WRITE_ONCE(ker_ff_ingress_listener, NULL);
	WRITE_ONCE(ker_ff_ingress_listener_cookie, 0);
	WRITE_ONCE(ker_ff_ingress_listener_mark, 0);
	atomic64_set(&ker_ff_ingress_attempt_count, 0);
	atomic64_set(&ker_ff_ingress_expired_count, 0);
	atomic64_set(&ker_ff_ingress_inventory_error_count, 0);
	misc_deregister(&ker_ff_admission_device);
	nf_unregister_net_hook(&init_net, &ker_ff_ingress_ops);
	nf_unregister_net_hook(&init_net, &ker_ff_admission_ops);
	if (ingress_listener)
		sock_put(ingress_listener);
}

module_init(ker_ff_admission_init);
module_exit(ker_ff_admission_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Private LKL local-output SYNACK admission queue");
