// clang-format off
//go:build ignore
// clang-format on
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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

#define RB_SUCCESS 0
#define RB_FAIL 1

static __always_inline __u8
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
