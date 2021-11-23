#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

struct vtep_val {
        __u8 eth_src_addr[6];
        __u8 eth_dst_addr[6];
        __be32 ipv4_src_addr;
        __be32 ipv4_dst_addr;
        __u16  vxlan_vni;
        __u8 action; // 1 - encap
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, 4);
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct vtep_val));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} vteps SEC(".maps");

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                         void *data_end,
				         struct ethhdr **ethhdr) {
        struct ethhdr *eth = nh->pos;
        if (eth + 1 > data_end)
                return -1;

        nh->pos += sizeof(*eth);
        *ethhdr = eth;
        return 0;
}

static __always_inline int parse_vxlanhdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct vxlanhdr **vxlanhdr) {
        struct vxlanhdr *vxlan = nh->pos;
        if (vxlan + 1 > data_end)
                return -1;

        nh->pos += sizeof(*vxlan);
        *vxlanhdr = vxlan;
        return 0;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	nh->pos  = h + 1;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

        *udphdr = h;

	return len;
}

SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    int output_port = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = NULL;
    struct ethhdr *inner_eth = NULL;
    struct iphdr *iphdr = NULL;
    struct udphdr *udphdr = NULL;
    struct vxlanhdr *vxlanhdr = NULL;
    struct hdr_cursor nh = { .pos = data };

    __u16 dport = 0;
    int ip_type = 0;
    __u8 eth_dst[6];
    __u8 vxlan_parsed = 0;

    int ret = 0;
    // Parser
    ret = parse_ethhdr(&nh, data_end, &eth);
    if (ret < 0) {
        return XDP_DROP;
    }
    __builtin_memcpy(&eth_dst, eth->h_dest, ETH_ALEN);

    __u16 h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
       ip_type = parse_iphdr(&nh, data_end, &iphdr);
       if (ip_type < 0)
           return XDP_DROP;
    } else {
       return XDP_DROP;
    }

    if (ip_type == IPPROTO_UDP) {
	ret = parse_udphdr(&nh, data_end, &udphdr);
        if (ret < 0)
            return XDP_DROP;
        dport = udphdr->dest;
        if (dport == bpf_ntohs(4789)) {
            ret = parse_vxlanhdr(&nh, data_end, &vxlanhdr);
            if (ret < 0) return XDP_DROP;
            vxlan_parsed = 1;
            ret = parse_ethhdr(&nh, data_end, &inner_eth);
            if (ret < 0) return XDP_DROP;
            __builtin_memcpy(&eth_dst, inner_eth->h_dest, ETH_ALEN);
        }
    }
    
    // Control
    if (vxlan_parsed == 1) {
        // decap VXLAN
        int ret = bpf_xdp_adjust_head(ctx, 50);
        if (ret < 0)
            return XDP_ABORTED;
    }

    int *out_port = bpf_map_lookup_elem(&l2fwd, &eth_dst);
    if (out_port != NULL) {
        output_port = *out_port;
    }

    struct vtep_val *val = bpf_map_lookup_elem(&vteps, &output_port);
    if (val != NULL) {
        if (val->action == 1) {
            int ret = bpf_xdp_adjust_head(ctx, -(int)50);
            if (ret < 0)
                return XDP_ABORTED;
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            struct ethhdr *out_eth = (struct ethhdr *) data;
            if (out_eth + 1 > data_end) return XDP_DROP;
            __builtin_memcpy(&out_eth->h_dest, val->eth_dst_addr, ETH_ALEN);
            __builtin_memcpy(&out_eth->h_source, val->eth_src_addr, ETH_ALEN);
            out_eth->h_proto = bpf_htons(ETH_P_IP);
            if (data + 50 + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return XDP_DROP;
            struct iphdr *out_ip = (struct iphdr *) (data + sizeof(struct ethhdr));
            __builtin_memmove(out_ip, data + 50 + sizeof(struct ethhdr), sizeof(struct iphdr));
            out_ip->daddr = bpf_htonl(val->ipv4_dst_addr);
            out_ip->saddr = bpf_htonl(val->ipv4_src_addr);
            out_ip->tot_len = out_ip->tot_len + 14 + 20 + sizeof(struct udphdr) + sizeof(vxlanhdr);
            out_ip->protocol = IPPROTO_UDP;
            struct udphdr *out_udp = (struct udphdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            out_udp->source = bpf_htons(4789);
            out_udp->dest = bpf_htons(4789);
            out_udp->len = out_ip->tot_len + 8 + 8 + 14;
            struct vxlanhdr *out_vxlan = (struct vxlanhdr *) (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(udphdr));
            __builtin_memset(out_vxlan, 0, sizeof(struct vxlanhdr));
            out_vxlan->vx_vni = bpf_htons(val->vxlan_vni);
        }
    }

    return bpf_redirect_map(&tx_port, output_port, 0);
}

char _license[] SEC("license") = "GPL";
