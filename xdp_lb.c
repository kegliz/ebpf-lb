// clang-format off
//go:build ignore
// clang-format on
#include "xdp_lb.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

#define INGRESS 0
#define EGRESS 1

struct event
{
  unsigned char direction;
  unsigned int addr;
};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

#define RB_SUCCESS 0
#define RB_FAIL 1

static __u8
write_ringbuf(__u8 direction, __u32 addr)
{
  struct event *packet_info;
  packet_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!packet_info)
  {
    bpf_printk("Failed to reserve ringbuf");
    return RB_FAIL;
  }
  packet_info->direction = direction;
  packet_info->addr = addr;
  bpf_ringbuf_submit(packet_info, 0);
  return RB_SUCCESS;
}

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
