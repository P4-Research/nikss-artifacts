#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

SEC("classifier/tc-ingress")
int tc_ingress_func(struct __sk_buff *skb) {
    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
