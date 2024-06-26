// clang-format off
//go:build ignore
// clang-format on
#include "xdp_lb.h"
#include "ringbuf.h"

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  bpf_printk("got something");

  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
    return XDP_ABORTED;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
    return XDP_PASS;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return XDP_ABORTED;

  if (iph->protocol != IPPROTO_TCP)
    return XDP_PASS;

  bpf_printk("Got TCP packet from %x", iph->saddr);

  if (write_ringbuf(INGRESS, iph->saddr) != RB_SUCCESS)
  {
    return XDP_ABORTED;
  }

  // If the packet is from the client, send it to one of the backends
  // If the packet is from one of the backends, send it to the client
  // Otherwise, pass the packet through
  if (iph->saddr == IP_ADDRESS(CLIENT))
  {
    char be = BACKEND_A;
    if (bpf_ktime_get_ns() % 2)
      be = BACKEND_B;

    iph->daddr = IP_ADDRESS(be);
    eth->h_dest[5] = be;
  }
  else if (iph->saddr == IP_ADDRESS(BACKEND_A) || iph->saddr == IP_ADDRESS(BACKEND_B))
  {
    iph->daddr = IP_ADDRESS(CLIENT);
    eth->h_dest[5] = CLIENT;
  }
  else
  {
    return XDP_PASS;
  }

  iph->saddr = IP_ADDRESS(LB);
  eth->h_source[5] = LB;

  iph->check = iph_csum(iph);

  bpf_printk("Send TCP packet to %x", iph->daddr);

  if (write_ringbuf(EGRESS, iph->daddr) != RB_SUCCESS)
  {
    return XDP_ABORTED;
  }

  return XDP_TX;
}

char _license[] SEC("license") = "Dual MIT/GPL";
