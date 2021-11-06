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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, sizeof(int));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l2fwd SEC(".maps");

SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    int *out_port = bpf_map_lookup_elem(&l2fwd, eth->h_dest);
    if (!out_port) {
        return XDP_DROP;
    }
    return bpf_redirect_map(&tx_port, *out_port, 0);
}

char _license[] SEC("license") = "GPL";
