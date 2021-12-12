
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

struct counter_val {
    __u32 bytes;
    __u32 packets;
};

struct ingress_vlan_key {
    __u32 ingress_port;
    __u32  vlan_valid;
} __attribute__((packed));

struct routable_key {
    __u8 dst_addr[6];
    __u16 vlan_id;
};

struct routing_key {
    __u32 prefixlen;
    __u32 addr;
} __attribute__((packed));

struct routing_val {
    __u8 src_addr[6];
    __u8 dst_addr[6];
    __u16 vlan_id;
};

struct switching_key {
    __u8 dst_addr[6];
    __u16 vlan_id;
};

struct acl_key {
    __u32 saddr;
    __u32 daddr;
    __u32 ip_proto;
    __u16 sport;
    __u16 dport;
};

struct bridged_metadata {
    __u32 ingress_port;
    __u16 vlan_id;
};


struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, 4);
    __uint(value_size, sizeof(struct bpf_devmap_val));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, 4);
    __uint(value_size, sizeof(struct counter_val));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} in_pkts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct acl_key));
    __uint(value_size, sizeof(int));  // 1 - forward, 2 - drop
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} acl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct switching_key));
    __uint(value_size, sizeof(int));  // output port
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} switching SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct routing_key)); // IPv4 dst addr
    __uint(value_size, sizeof(struct routing_val));
    __uint(max_entries, 100);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} routing SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct routable_key));
    __uint(value_size, sizeof(__u8));  // whatever
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} routable SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ingress_vlan_key));
    __uint(value_size, sizeof(__u16));  // vlan_id
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_vlan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u8));  // action, 1 - push_vlan
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_vlan SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, ETH_ALEN);
    __uint(value_size, sizeof(int));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l2fwd SEC(".maps");

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

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

static __always_inline int parse_vlanhdr(struct hdr_cursor *nh, void *data_end, struct vlan_hdr **vlanhdr) {
	struct vlan_hdr *vlan = nh->pos;
        if (vlan + 1 > data_end) 
		return -1;
	nh->pos += sizeof(*vlan);
        *vlanhdr = vlan;
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

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return len;
}



SEC("xdp/xdp-ingress")
int xdp_func(struct xdp_md *ctx)
{
    int in_port = ctx->ingress_ifindex;
    int out_port = -1;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    unsigned long pkt_len = (unsigned long) data_end - (unsigned long) data;

    __u64 nh_off;

    __u16 vlanhdr_vlan_id = 0;
    __u32 ip_saddr = 0, ip_daddr = 0;
    __u16 sport = 0, dport = 0;
    __u32 ip_proto = 0;
    int ip_type = 0;

    struct ethhdr *eth = NULL;
    struct vlan_hdr *vlanhdr = NULL;
    struct iphdr *iphdr = NULL;
    struct udphdr *udphdr = NULL;
    struct tcphdr *tcphdr = NULL;
    struct hdr_cursor nh = { .pos = data };

    __u8 vlan_exists = 0;
    int ret = 0;
    // Parser
    ret = parse_ethhdr(&nh, data_end, &eth);
    if (ret < 0) {
        return XDP_DROP;
    }
    __u16 h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        ret = parse_vlanhdr(&nh, data_end, &vlanhdr);
        if (ret < 0)
	    return XDP_DROP;
        vlan_exists = 1;
        h_proto = vlanhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
       ip_type = parse_iphdr(&nh, data_end, &iphdr);
       if (ip_type < 0)
           return XDP_DROP;
       ip_proto = iphdr->protocol;
       ip_saddr = iphdr->saddr;
       ip_daddr = iphdr->daddr;
    } else {
       return XDP_DROP;
    }

    if (ip_type == IPPROTO_UDP) {
	ret = parse_udphdr(&nh, data_end, &udphdr);
        if (ret < 0)
            return XDP_DROP;
        sport = udphdr->source;
        dport = udphdr->dest;
    } else if (ip_type == IPPROTO_TCP) {
        ret = parse_tcphdr(&nh, data_end, &tcphdr);
        if (ret < 0)
            return XDP_DROP;
        sport = tcphdr->source;
        dport = tcphdr->dest;
    }

    // Control block
    struct counter_val *ctr_val = bpf_map_lookup_elem(&in_pkts, &in_port);
    if (ctr_val != NULL) {
	__sync_fetch_and_add(&(ctr_val->bytes), (__u32) pkt_len);
        __sync_fetch_and_add(&(ctr_val->packets), 1);
    }


    struct ingress_vlan_key k_ingress_vlan = {
        .ingress_port = in_port,
        .vlan_valid = vlan_exists,
    };

    __u16 *vlan_id = bpf_map_lookup_elem(&ingress_vlan, &k_ingress_vlan);
    if (vlan_id != NULL) {
        vlanhdr_vlan_id = *vlan_id;
    }
    struct routable_key k_routable = {
        .vlan_id = vlanhdr_vlan_id,
    };
    __builtin_memcpy(&(k_routable.dst_addr), eth->h_dest, ETH_ALEN);
    __u8 *routing_enabled = bpf_map_lookup_elem(&routable, &k_routable);
    if (routing_enabled != NULL) {
        struct routing_key k_routing = {};
        __builtin_memset(&k_routing, 0, sizeof(k_routing));
        k_routing.prefixlen = 32;
        k_routing.addr = ip_daddr;
        struct routing_val *val = bpf_map_lookup_elem(&routing, &k_routing);
        if (val != NULL) {
            __builtin_memcpy(eth->h_source, val->src_addr, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, val->dst_addr, ETH_ALEN);
            vlanhdr_vlan_id = val->vlan_id;
            if (iphdr->ttl == 0) {
		return XDP_DROP;
            }
        }
    }

    struct switching_key k_switching = {
        .vlan_id = vlanhdr_vlan_id,
    };
    __builtin_memcpy(&(k_switching.dst_addr), eth->h_dest, ETH_ALEN);

    int *output_port = bpf_map_lookup_elem(&switching, &k_switching);
    if (output_port) {
	out_port = *output_port;
    }

    struct acl_key k_acl = {};
    k_acl.saddr = ip_saddr;
    k_acl.daddr = ip_daddr;
    k_acl.ip_proto = (__u32) ip_proto;
    k_acl.sport = sport;
    k_acl.dport = dport;

    int *action = bpf_map_lookup_elem(&acl, &k_acl);
    if (action != NULL) {
        if (*action == 2) // drop
            return XDP_DROP;
    }

    // unfortunately it seems that data_meta cannot be used
    ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct bridged_metadata));
    if (ret < 0)
	return XDP_ABORTED;

    data = (void *)(unsigned long)ctx->data;
    data_end = (void *)(unsigned long)ctx->data_end;

    struct bridged_metadata *meta = data;
    if (data + sizeof(struct bridged_metadata) > data_end)
		return XDP_ABORTED;

    meta->ingress_port = in_port;
    meta->vlan_id = vlanhdr_vlan_id;

    return bpf_redirect_map(&tx_port, out_port, 0);
}

SEC("xdp_devmap/xdp-egress")
int xdp_func_egress(struct xdp_md *ctx) {
    void *data = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    struct bridged_metadata *meta = data;
    if (meta + 1 > data_end)
                return XDP_ABORTED;

    __u32 in_port = meta->ingress_port;
    __u32 vlan_id = meta->vlan_id;

    int ret = bpf_xdp_adjust_head(ctx, sizeof(struct bridged_metadata));
    if (ret < 0)
        return XDP_ABORTED;

    if (ctx->egress_ifindex == in_port) {
        return XDP_DROP;
    }
    int out_port = ctx->egress_ifindex;
    int *action = bpf_map_lookup_elem(&egress_vlan, &out_port);
    if (action != NULL) {
        if (*action == 1) { // TODO: push_vlan, we don't use VLANs
            /*
            ret = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr));
    	    if (ret < 0)
        	return XDP_ABORTED;
            data = (void *)(unsigned long)ctx->data;
    	    data_end = (void *)(unsigned long)ctx->data_end;

	    __builtin_memmove(data, data + sizeof(struct vlan_hdr), sizeof(struct ethhdr));
	    */
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
