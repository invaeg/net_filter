
#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

MODULE_AUTHOR("Ashish Tyagi");
MODULE_DESCRIPTION("Log ICMP messages");
MODULE_LICENSE("COPY_LEFT");

static struct nf_hook_ops hook_data;
static long drop_all = 0;


static unsigned int hook_func(
  void *priv,
  struct sk_buff *skb,
  const struct nf_hook_state *state
) {
  struct iphdr *ip_header;
  struct icmphdr *icmp_header;
  if (!skb)
    return NF_ACCEPT;
  ip_header = (struct iphdr *)skb_network_header(skb);
  if (ip_header->protocol == IPPROTO_ICMP) {
    icmp_header = (struct icmphdr *)(skb_transport_header(skb) +
        ip_hdrlen(skb));
    pr_info("SRC: (%pI4) --> DST: (%pI4) ICMP type: %d - ICMP code: %d\n",
          &ip_header->saddr,
          &ip_header->daddr,
          icmp_header ? icmp_header->type : 0,
          icmp_header ? icmp_header->code : 0
    );
  }
  return drop_all == 0 ? NF_ACCEPT : NF_DROP;
}

static int __init mod_init(void)
{
  int retcode = 0;
  hook_data.hook = hook_func;
  hook_data.hooknum = NF_INET_PRE_ROUTING;
  hook_data.pf = PF_INET;
  hook_data.priority = NF_IP_PRI_LAST;
  retcode = nf_register_net_hook(&init_net, &hook_data);
  if (retcode) {
    pr_err("Failed to register NetFilter hook\n");
    return retcode;
  }

  pr_info("Registered NetFilter Module\n");

  return retcode;
}

static void __exit mod_exit(void)
{
  nf_unregister_net_hook(&init_net, &hook_data);
  pr_info("Unregistered NetFilter Module\n");
}

module_init(mod_init);
module_exit(mod_exit);
