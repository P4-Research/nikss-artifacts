#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 100);
       __uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");


SEC("xdp/xdp-ingress")
int ingress_func(struct xdp_md *skb) {
    int port = 17;
    return bpf_redirect_map(&tx_port, port, 0);
}

char _license[] SEC("license") = "GPL";
