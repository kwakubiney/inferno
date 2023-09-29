#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 20000);
} blocked SEC(".maps");


SEC("tc/ingress")
int process_ingress_pkt(struct __sk_buff *skb){
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data > data_end) {
        return TC_ACT_SHOT;
    }

    struct ethhdr *eth_hdr = data;

    if ((void *) (eth_hdr + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth_hdr->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end){
  		return TC_ACT_SHOT;
	}

	long *blocked_ip;
    struct iphdr *ip = (data + sizeof(struct ethhdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_SHOT;
    }

    blocked_ip = bpf_map_lookup_elem(&blocked, &(ip->saddr));
	if (blocked_ip == NULL) {
         return TC_ACT_OK;
    }else{
	    return TC_ACT_SHOT;
    }
}

char __license[] SEC("license") = "GPL";