// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <net/net_namespace.h>
#include <uapi/asm/ker_ff_admission_queue.h>

static_assert(sizeof(struct ker_ff_admission_queue_control) == 32);

static u64 ker_ff_admission_state;
static atomic64_t ker_ff_admission_next_lease = ATOMIC64_INIT(0);
static u64 ker_ff_admission_lease;
static DEFINE_MUTEX(ker_ff_admission_control_lock);

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
	if (command != KER_FF_ADMISSION_QUEUE_SET)
		return -ENOTTY;
	return ker_ff_admission_set(argument);
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
	error = misc_register(&ker_ff_admission_device);
	if (error)
		nf_unregister_net_hook(&init_net, &ker_ff_admission_ops);
	return error;
}

static void __exit ker_ff_admission_exit(void)
{
	WRITE_ONCE(ker_ff_admission_state, 0);
	ker_ff_admission_lease = 0;
	misc_deregister(&ker_ff_admission_device);
	nf_unregister_net_hook(&init_net, &ker_ff_admission_ops);
}

module_init(ker_ff_admission_init);
module_exit(ker_ff_admission_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Private LKL local-output SYNACK admission queue");
