#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct bpf_map_def SEC("maps") = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(u32),
      .value_size  = sizeof(u64),
      .max_entries = 20000,
      .map_flags   = 0
};

SEC("ingress")
int process_ingress_pkt(struct __sk_buff *skb){
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    return TC_ACT_UNSPEC;

    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    bpf_skb_load_bytes(skb, 0, ip, sizeof(struct iphdr));
    bool notFound = bpf_lookup_elem(&deny, &iph.s_addr)

    if (!notFound){
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";