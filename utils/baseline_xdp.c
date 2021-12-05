#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

SEC("xdp/xdp-ingress")
int ingress_func(struct xdp_md *skb) {
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
