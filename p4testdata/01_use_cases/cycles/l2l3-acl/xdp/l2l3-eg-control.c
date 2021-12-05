#include "ebpf_kernel.h"

#include <stdbool.h>
#include <linux/if_ether.h>
#include "psa.h"

#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define write_partial(a, w, s, v) do { *((u8*)a) = ((*((u8*)a)) & ~(EBPF_MASK(u8, w) << s)) | (v << s) ; } while (0)
#define write_byte(base, offset, v) do { *(u8*)((base) + (offset)) = (v); } while (0)
#define bpf_trace_message(fmt, ...)

#define CLONE_MAX_PORTS 64
#define CLONE_MAX_INSTANCES 1
#define CLONE_MAX_CLONES (CLONE_MAX_PORTS * CLONE_MAX_INSTANCES)
#define CLONE_MAX_SESSIONS 1024
#define DEVMAP_SIZE 256

#ifndef PSA_PORT_RECIRCULATE
#error "PSA_PORT_RECIRCULATE not specified, please use -DPSA_PORT_RECIRCULATE=n option to specify index of recirculation interface (see the result of command 'ip link')"
#endif
#define P4C_PSA_PORT_RECIRCULATE 0xfffffffa

struct internal_metadata {
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));

struct list_key_t {
    __u32 port;
    __u16 instance;
};
typedef struct list_key_t elem_t;

struct element {
    struct clone_session_entry entry;
    elem_t next_id;
} __attribute__((aligned(4)));


struct empty_metadata_t {
};
struct ethernet_t {
    u64 dst_addr; /* ethernet_addr_t */
    u64 src_addr; /* ethernet_addr_t */
    u16 ether_type; /* bit<16> */
    u8 ebpf_valid;
};
struct vlan_tag_t {
    u8 pri; /* bit<3> */
    u8 cfi; /* bit<1> */
    u16 vlan_id; /* vlan_id_t */
    u16 eth_type; /* bit<16> */
    u8 ebpf_valid;
};
struct ipv4_t {
    u8 ver_ihl; /* bit<8> */
    u8 diffserv; /* bit<8> */
    u16 total_len; /* bit<16> */
    u16 identification; /* bit<16> */
    u16 flags_offset; /* bit<16> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdr_checksum; /* bit<16> */
    u32 src_addr; /* bit<32> */
    u32 dst_addr; /* bit<32> */
    u8 ebpf_valid;
};
struct tcp_t {
    u16 sport; /* bit<16> */
    u16 dport; /* bit<16> */
    u32 seq_no; /* bit<32> */
    u32 ack_no; /* bit<32> */
    u8 data_offset; /* bit<4> */
    u8 res; /* bit<3> */
    u8 ecn; /* bit<3> */
    u8 ctrl; /* bit<6> */
    u16 window; /* bit<16> */
    u16 checksum; /* bit<16> */
    u16 urgent_ptr; /* bit<16> */
    u8 ebpf_valid;
};
struct udp_t {
    u16 sport; /* bit<16> */
    u16 dport; /* bit<16> */
    u16 len; /* bit<16> */
    u16 checksum; /* bit<16> */
    u8 ebpf_valid;
};
struct bridged_md_t {
    u32 ingress_port; /* bit<32> */
    u8 ebpf_valid;
};
struct headers_t {
    struct bridged_md_t bridged_meta; /* bridged_md_t */
    struct ethernet_t ethernet; /* ethernet_t */
    struct vlan_tag_t vlan_tag; /* vlan_tag_t */
    struct ipv4_t ipv4; /* ipv4_t */
    struct tcp_t tcp; /* tcp_t */
    struct udp_t udp; /* udp_t */
__u32 __helper_variable;
};
struct mac_learn_digest_t {
    u64 mac_addr; /* ethernet_addr_t */
    u32 port; /* PortId_t */
    u16 vlan_id; /* vlan_id_t */
};
struct local_metadata_t {
    u8 send_mac_learn_msg; /* bool */
    struct mac_learn_digest_t mac_learn_msg; /* mac_learn_digest_t */
    u16 l4_sport; /* bit<16> */
    u16 l4_dport; /* bit<16> */
};
struct tuple_0 {
    u8 f0; /* bit<8> */
    u8 f1; /* bit<8> */
};
struct hdr_md {
    struct headers_t cpumap_hdr;
    struct local_metadata_t cpumap_usermeta;
    __u8 __hook;
};
struct xdp2tc_metadata {
    struct headers_t headers;
    struct psa_ingress_output_metadata_t ostd;
    __u32 packetOffsetInBits;
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));


#define INGRESS_AS_ACT_INGRESS_SET_NEXTHOP 1
struct ingress_as_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u64 smac;
            u64 dmac;
            u16 vlan_id;
        } ingress_set_nexthop;
    } u;
};
struct ingress_tbl_acl_key {
    u32 field0; /* headers.ipv4.src_addr */
    u32 field1; /* headers.ipv4.dst_addr */
    u8 field2; /* headers.ipv4.protocol */
    u16 field3; /* local_metadata.l4_sport */
    u16 field4; /* local_metadata.l4_dport */
} __attribute__((aligned(4)));
#define INGRESS_TBL_ACL_ACT_INGRESS_DROP 1
struct ingress_tbl_acl_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } ingress_drop;
    } u;
};
struct ingress_tbl_ingress_vlan_key {
    u32 field0; /* standard_metadata.ingress_port */
    u8 field1; /*     headers.vlan_tag.ebpf_valid */
} __attribute__((aligned(4)));
#define INGRESS_TBL_INGRESS_VLAN_ACT_INGRESS_PUSH_VLAN 1
struct ingress_tbl_ingress_vlan_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } ingress_push_vlan;
    } u;
};
struct ingress_tbl_mac_learning_key {
    u64 field0; /* headers.ethernet.src_addr */
} __attribute__((aligned(4)));
#define INGRESS_TBL_MAC_LEARNING_ACT_INGRESS_MAC_LEARN 1
struct ingress_tbl_mac_learning_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } ingress_mac_learn;
    } u;
};
struct ingress_tbl_routable_key {
    u64 field0; /* headers.ethernet.dst_addr */
    u16 field1; /* headers.vlan_tag.vlan_id */
} __attribute__((aligned(4)));
struct ingress_tbl_routable_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
    } u;
};
struct ingress_tbl_routing_key {
    u32 prefixlen;
    u32 field0; /* headers.ipv4.dst_addr */
    /* headers.ipv4.src_addr : selector */
    /* local_metadata.l4_sport : selector */
} __attribute__((aligned(4)));
#define INGRESS_TBL_ROUTING_ACT_INGRESS_SET_NEXTHOP 1
struct ingress_tbl_routing_value {
    u32 ingress_as_ref;
    u32 ingress_as_is_group_ref;
};
struct ingress_tbl_switching_key {
    u64 field0; /* headers.ethernet.dst_addr */
    u16 field1; /* headers.vlan_tag.vlan_id */
} __attribute__((aligned(4)));
#define INGRESS_TBL_SWITCHING_ACT_INGRESS_FORWARD 1
#define INGRESS_TBL_SWITCHING_ACT_INGRESS_BROADCAST 2
struct ingress_tbl_switching_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u32 output_port;
        } ingress_forward;
        struct {
            u32 grp_id;
        } ingress_broadcast;
    } u;
};
typedef u32 ingress_in_pkts_key;
typedef struct {
    u32 bytes;
    u32 packets;
} ingress_in_pkts_value;
struct egress_tbl_vlan_egress_key {
    u32 field0; /* istd.egress_port */
} __attribute__((aligned(4)));
#define EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_STRIP_VLAN 1
#define EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_MOD_VLAN 2
struct egress_tbl_vlan_egress_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } egress_strip_vlan;
        struct {
            u16 vlan_id;
        } egress_mod_vlan;
    } u;
    struct {
        u32 bytes;
        u32 packets;
    } egress_out_pkts;
};

struct bpf_map_def SEC("maps") tx_port = {
    .type          = BPF_MAP_TYPE_DEVMAP,
    .key_size      = sizeof(int),
    .value_size    = sizeof(struct bpf_devmap_val),
    .max_entries   = DEVMAP_SIZE,
};

REGISTER_START()
REGISTER_TABLE_INNER(clone_session_tbl_inner, BPF_MAP_TYPE_HASH, elem_t, struct element, 64, 1, 1)
BPF_ANNOTATE_KV_PAIR(clone_session_tbl_inner, elem_t, struct element)
REGISTER_TABLE_OUTER(clone_session_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, __u32, __u32, 1024, 1, clone_session_tbl_inner)
BPF_ANNOTATE_KV_PAIR(clone_session_tbl, __u32, __u32)
REGISTER_TABLE_INNER(multicast_grp_tbl_inner, BPF_MAP_TYPE_HASH, elem_t, struct element, 64, 2, 2)
BPF_ANNOTATE_KV_PAIR(multicast_grp_tbl_inner, elem_t, struct element)
REGISTER_TABLE_OUTER(multicast_grp_tbl, BPF_MAP_TYPE_ARRAY_OF_MAPS, __u32, __u32, 1024, 2, multicast_grp_tbl_inner)
BPF_ANNOTATE_KV_PAIR(multicast_grp_tbl, __u32, __u32)
REGISTER_TABLE_INNER(ingress_as_groups_inner, BPF_MAP_TYPE_ARRAY, u32, u32, 129, 3, 3)
BPF_ANNOTATE_KV_PAIR(ingress_as_groups_inner, u32, u32)
REGISTER_TABLE_OUTER(ingress_as_groups, BPF_MAP_TYPE_HASH_OF_MAPS, u32, __u32, 1024, 3, ingress_as_groups_inner)
BPF_ANNOTATE_KV_PAIR(ingress_as_groups, u32, __u32)
REGISTER_TABLE(ingress_as_defaultActionGroup, BPF_MAP_TYPE_ARRAY, u32, struct ingress_as_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_as_defaultActionGroup, u32, struct ingress_as_value)
REGISTER_TABLE(ingress_as_actions, BPF_MAP_TYPE_HASH, u32, struct ingress_as_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_as_actions, u32, struct ingress_as_value)
REGISTER_TABLE(ingress_tbl_acl, BPF_MAP_TYPE_HASH, struct ingress_tbl_acl_key, struct ingress_tbl_acl_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_acl, struct ingress_tbl_acl_key, struct ingress_tbl_acl_value)
REGISTER_TABLE(ingress_tbl_acl_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_tbl_acl_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_acl_defaultAction, u32, struct ingress_tbl_acl_value)
REGISTER_TABLE(ingress_tbl_ingress_vlan, BPF_MAP_TYPE_HASH, struct ingress_tbl_ingress_vlan_key, struct ingress_tbl_ingress_vlan_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_ingress_vlan, struct ingress_tbl_ingress_vlan_key, struct ingress_tbl_ingress_vlan_value)
REGISTER_TABLE(ingress_tbl_ingress_vlan_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_tbl_ingress_vlan_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_ingress_vlan_defaultAction, u32, struct ingress_tbl_ingress_vlan_value)
REGISTER_TABLE(ingress_tbl_mac_learning, BPF_MAP_TYPE_HASH, struct ingress_tbl_mac_learning_key, struct ingress_tbl_mac_learning_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_mac_learning, struct ingress_tbl_mac_learning_key, struct ingress_tbl_mac_learning_value)
REGISTER_TABLE(ingress_tbl_mac_learning_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_tbl_mac_learning_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_mac_learning_defaultAction, u32, struct ingress_tbl_mac_learning_value)
REGISTER_TABLE(ingress_tbl_routable, BPF_MAP_TYPE_HASH, struct ingress_tbl_routable_key, struct ingress_tbl_routable_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_routable, struct ingress_tbl_routable_key, struct ingress_tbl_routable_value)
REGISTER_TABLE(ingress_tbl_routable_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_tbl_routable_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_routable_defaultAction, u32, struct ingress_tbl_routable_value)
REGISTER_TABLE_FLAGS(ingress_tbl_routing, BPF_MAP_TYPE_LPM_TRIE, struct ingress_tbl_routing_key, struct ingress_tbl_routing_value, 1024, BPF_F_NO_PREALLOC)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_routing, struct ingress_tbl_routing_key, struct ingress_tbl_routing_value)
REGISTER_TABLE(ingress_tbl_switching, BPF_MAP_TYPE_HASH, struct ingress_tbl_switching_key, struct ingress_tbl_switching_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_switching, struct ingress_tbl_switching_key, struct ingress_tbl_switching_value)
REGISTER_TABLE(ingress_tbl_switching_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_tbl_switching_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_tbl_switching_defaultAction, u32, struct ingress_tbl_switching_value)
REGISTER_TABLE(ingress_in_pkts, BPF_MAP_TYPE_ARRAY, u32, ingress_in_pkts_value, 100)
BPF_ANNOTATE_KV_PAIR(ingress_in_pkts, u32, ingress_in_pkts_value)
REGISTER_TABLE_NO_KEY_TYPE(mac_learn_digest_0, BPF_MAP_TYPE_QUEUE, 0, struct mac_learn_digest_t , 100)
REGISTER_TABLE(egress_tbl_vlan_egress, BPF_MAP_TYPE_HASH, struct egress_tbl_vlan_egress_key, struct egress_tbl_vlan_egress_value, 1024)
BPF_ANNOTATE_KV_PAIR(egress_tbl_vlan_egress, struct egress_tbl_vlan_egress_key, struct egress_tbl_vlan_egress_value)
REGISTER_TABLE(egress_tbl_vlan_egress_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct egress_tbl_vlan_egress_value, 1)
BPF_ANNOTATE_KV_PAIR(egress_tbl_vlan_egress_defaultAction, u32, struct egress_tbl_vlan_egress_value)
REGISTER_TABLE(xdp2tc_shared_map, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct xdp2tc_metadata, 1)
BPF_ANNOTATE_KV_PAIR(xdp2tc_shared_map, u32, struct xdp2tc_metadata)
REGISTER_TABLE(hdr_md_cpumap, BPF_MAP_TYPE_PERCPU_ARRAY, u32, struct hdr_md, 2)
BPF_ANNOTATE_KV_PAIR(hdr_md_cpumap, u32, struct hdr_md)
REGISTER_END()

static __always_inline
void crc16_update(u16 * reg, const u8 * data, u16 data_size, const u16 poly) {
    data += data_size - 1;
    for (u16 i = 0; i < data_size; i++) {
        bpf_trace_message("CRC16: data byte: %x\n", *data);
        *reg ^= *data;
        for (u8 bit = 0; bit < 8; bit++) {
            *reg = (*reg) & 1 ? ((*reg) >> 1) ^ poly : (*reg) >> 1;
        }
        data--;
    }
}
static __always_inline u16 crc16_finalize(u16 reg, const u16 poly) {
    return reg;
}
static __always_inline
void crc32_update(u32 * reg, const u8 * data, u16 data_size, const u32 poly) {
    data += data_size - 1;
    for (u16 i = 0; i < data_size; i++) {
        bpf_trace_message("CRC32: data byte: %x\n", *data);
        *reg ^= *data;
        for (u8 bit = 0; bit < 8; bit++) {
            *reg = (*reg) & 1 ? ((*reg) >> 1) ^ poly : (*reg) >> 1;
        }
        data--;
    }
}
static __always_inline u32 crc32_finalize(u32 reg, const u32 poly) {
    return reg ^ 0xFFFFFFFF;
}
inline u16 csum16_add(u16 csum, u16 addend) {
    u16 res = csum;
    res += addend;
    return (res + (res < addend));
}
inline u16 csum16_sub(u16 csum, u16 addend) {
    return csum16_add(csum, ~addend);
}
static __always_inline
int do_for_each(SK_BUFF *skb, void *map, unsigned int max_iter, void (*a)(SK_BUFF *, void *))
{
    elem_t head_idx = {0, 0};
    struct element *elem = bpf_map_lookup_elem(map, &head_idx);
    if (!elem) {
        return -1;
    }
    if (elem->next_id.port == 0 && elem->next_id.instance == 0) {
               return 0;
    }
    elem_t next_id = elem->next_id;
    for (unsigned int i = 0; i < max_iter; i++) {
        struct element *elem = bpf_map_lookup_elem(map, &next_id);
        if (!elem) {
            break;
        }
        a(skb, &elem->entry);
        if (elem->next_id.port == 0 && elem->next_id.instance == 0) {
            break;
        }
        next_id = elem->next_id;
    }
    return 0;
}

static __always_inline
void do_clone(SK_BUFF *skb, void *data)
{
    struct clone_session_entry *entry = (struct clone_session_entry *) data;
    bpf_clone_redirect(skb, entry->egress_port, 0);
}

static __always_inline
int do_packet_clones(SK_BUFF * skb, void * map, __u32 session_id, PSA_PacketPath_t new_pkt_path, __u8 caller_id)
{
    struct psa_global_metadata * meta = (struct psa_global_metadata *) skb->cb;
    void * inner_map;
    inner_map = bpf_map_lookup_elem(map, &session_id);
    if (inner_map != NULL) {
        PSA_PacketPath_t original_pkt_path = meta->packet_path;
        meta->packet_path = new_pkt_path;
        if (do_for_each(skb, inner_map, CLONE_MAX_CLONES, &do_clone) < 0) {
            return -1;
        }
        meta->packet_path = original_pkt_path;
    } else {
    }
    return 0;
 }

SEC("xdp/map-initializer")
int map_initialize() {
    u32 ebpf_zero = 0;
    struct ingress_tbl_mac_learning_value value_0 = {
        .action = INGRESS_TBL_MAC_LEARNING_ACT_INGRESS_MAC_LEARN,
        .u = {.ingress_mac_learn = {}},
    };
    int ret = BPF_MAP_UPDATE_ELEM(ingress_tbl_mac_learning_defaultAction, &ebpf_zero, &value_0, BPF_ANY);
    if (ret) {
    } else {
    }

    return 0;
}

SEC("xdp_ingress/xdp-ingress")
int xdp_ingress_func(struct xdp_md *skb) {
    struct empty_metadata_t resubmit_meta;

    struct hdr_md *hdrMd;
    struct headers_t *headers;
    struct local_metadata_t *local_metadata;

    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->data_end - skb->data;
    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_zero);
    if (!hdrMd)
        return XDP_DROP;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    headers = &(hdrMd->cpumap_hdr);
    local_metadata = &(hdrMd->cpumap_usermeta);
    struct psa_ingress_output_metadata_t ostd = {
            .drop = true,
    };

    u16 ck_0_state = 0;
    start: {
/* extract(headers->ethernet) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->ethernet.dst_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.src_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.ether_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ethernet.ebpf_valid = 1;

        switch (headers->ethernet.ether_type) {
            case 2048: goto parse_ipv4;
            case 33024: goto parse_vlan;
            default: goto accept;
        }
    }
    parse_vlan: {
/* extract(headers->vlan_tag) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->vlan_tag.pri = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers->vlan_tag.cfi = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        headers->vlan_tag.vlan_id = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 12));
        ebpf_packetOffsetInBits += 12;

        headers->vlan_tag.eth_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->vlan_tag.ebpf_valid = 1;

        switch (headers->vlan_tag.eth_type) {
            case 2048: goto parse_ipv4;
            default: goto accept;
        }
    }
    parse_ipv4: {
/* extract(headers->ipv4) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->ipv4.ver_ihl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.diffserv = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.total_len = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.identification = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.flags_offset = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.protocol = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.hdr_checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.src_addr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->ipv4.dst_addr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->ipv4.ebpf_valid = 1;

/* ck_0.subtract(headers->ipv4.hdr_checksum) */
        {
            u16 ck_0_tmp = 0;
            ck_0_tmp = headers->ipv4.hdr_checksum;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp);
        }
/* ck_0.subtract(headers->ipv4.ttl, headers->ipv4.protocol) */
        {
            u16 ck_0_tmp_0 = 0;
            ck_0_tmp_0 = (headers->ipv4.ttl << 8) | headers->ipv4.protocol;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp_0);
        }
headers->ipv4.hdr_checksum = /* ck_0.get() */
((u16) (~ck_0_state));        switch (headers->ipv4.protocol) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            default: goto accept;
        }
    }
    parse_tcp: {
/* extract(headers->tcp) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->tcp.sport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.dport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.seq_no = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->tcp.ack_no = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->tcp.data_offset = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        headers->tcp.res = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 1) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers->tcp.ecn = (u8)((load_half(pkt, BYTES(ebpf_packetOffsetInBits)) >> 6) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers->tcp.ctrl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 6));
        ebpf_packetOffsetInBits += 6;

        headers->tcp.window = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.urgent_ptr = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.ebpf_valid = 1;

local_metadata->l4_sport = headers->tcp.sport;local_metadata->l4_dport = headers->tcp.dport;        goto accept;
    }
    parse_udp: {
/* extract(headers->udp) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->udp.sport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->udp.dport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->udp.len = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->udp.checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->udp.ebpf_valid = 1;

local_metadata->l4_sport = headers->udp.sport;local_metadata->l4_dport = headers->udp.dport;        goto accept;
    }

    reject: {
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }


    accept: {
        struct psa_ingress_input_metadata_t standard_metadata = {
            .ingress_port = skb->ingress_ifindex,
            .packet_path = 0,
            .parser_error = ebpf_errorCode,
    };
        u8 hit_3;
        u8 hasExited;
        struct psa_ingress_output_metadata_t meta_4;
        __builtin_memset((void *) &meta_4, 0, sizeof(struct psa_ingress_output_metadata_t ));
        struct psa_ingress_output_metadata_t meta_5;
        __builtin_memset((void *) &meta_5, 0, sizeof(struct psa_ingress_output_metadata_t ));
        struct psa_ingress_output_metadata_t meta_6;
        __builtin_memset((void *) &meta_6, 0, sizeof(struct psa_ingress_output_metadata_t ));
        u32 egress_port_1;
        struct psa_ingress_output_metadata_t meta_7;
        __builtin_memset((void *) &meta_7, 0, sizeof(struct psa_ingress_output_metadata_t ));
        u32 multicast_group_1;
        {
hasExited = false;
            {
                ingress_in_pkts_value *value_1;
                ingress_in_pkts_key key_0 = (u32)standard_metadata.ingress_port;
                value_1 = BPF_MAP_LOOKUP_ELEM(ingress_in_pkts, &key_0);
                if (value_1 != NULL) {
                    __sync_fetch_and_add(&(value_1->bytes), pkt_len);
                    __sync_fetch_and_add(&(value_1->packets), 1);
                } else {
                }
            };
                        {
                /* construct key */
                struct ingress_tbl_ingress_vlan_key key = {};
                key.field0 = standard_metadata.ingress_port;
                key.field1 =                 headers->vlan_tag.ebpf_valid;
                /* value */
                struct ingress_tbl_ingress_vlan_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_ingress_vlan, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_ingress_vlan_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_TBL_INGRESS_VLAN_ACT_INGRESS_PUSH_VLAN: 
                            {
                                headers->vlan_tag.ebpf_valid = true;
                                headers->vlan_tag.eth_type = headers->ethernet.ether_type;
                                headers->ethernet.ether_type = 33024;
                            }
                            break;
                        case 0: 
                            {
                            }
                            break;
                        default:
                            return XDP_ABORTED;
                    }
                } else {
                    return XDP_ABORTED;
                }
            }
;
                        {
                /* construct key */
                struct ingress_tbl_mac_learning_key key = {};
                key.field0 = headers->ethernet.src_addr;
                /* value */
                struct ingress_tbl_mac_learning_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_mac_learning, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_mac_learning_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_TBL_MAC_LEARNING_ACT_INGRESS_MAC_LEARN: 
                            {
local_metadata->send_mac_learn_msg = true;
                                local_metadata->mac_learn_msg.mac_addr = headers->ethernet.src_addr;
                                local_metadata->mac_learn_msg.port = standard_metadata.ingress_port;
                                local_metadata->mac_learn_msg.vlan_id = headers->vlan_tag.vlan_id;
                            }
                            break;
                        case 0: 
                            {
                            }
                            break;
                        default:
                            return XDP_ABORTED;
                    }
                } else {
                    return XDP_ABORTED;
                }
            }
;
                        {
                /* construct key */
                struct ingress_tbl_routable_key key = {};
                key.field0 = headers->ethernet.dst_addr;
                key.field1 = headers->vlan_tag.vlan_id;
                /* value */
                struct ingress_tbl_routable_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_routable, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_routable_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case 0: 
                            {
                            }
                            break;
                        default:
                            return XDP_ABORTED;
                    }
                } else {
                    return XDP_ABORTED;
                }
            }
            if (hit_3) {
                unsigned int action_run = 0;
                {
                    /* construct key */
                    struct ingress_tbl_routing_key key = {};
                    key.prefixlen = sizeof(key)*8 - 32;
                    u32 tmp_field0 = headers->ipv4.dst_addr;
                    key.field0 = bpf_htonl(tmp_field0);
                    /* value */
                    struct ingress_tbl_routing_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_routing, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        /* table with implementation has no default action */
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        struct ingress_as_value * as_value = NULL;
                        u32 as_action_ref = value->ingress_as_ref;
                        u8 as_group_state = 0;
                        if (value->ingress_as_is_group_ref != 0) {
                            void * as_group_map = BPF_MAP_LOOKUP_ELEM(ingress_as_groups, &as_action_ref);
                            if (as_group_map != NULL) {
                                u32 * as_map_entry = bpf_map_lookup_elem(as_group_map, &ebpf_zero);
                                if (as_map_entry != NULL) {
                                    if (*as_map_entry != 0) {
                                        u32 ingress_as_hash_reg = 0xffffffff;
                                        {
                                            u8 ingress_as_hash_tmp = 0;
                                            crc32_update(&ingress_as_hash_reg, (u8 *) &(headers->ipv4.src_addr), 4, 3988292384);
                                            crc32_update(&ingress_as_hash_reg, (u8 *) &(local_metadata->l4_sport), 2, 3988292384);
                                        }
                                        u64 as_checksum_val = crc32_finalize(ingress_as_hash_reg, 3988292384) & 0xffff;
                                        as_action_ref = 1 + (as_checksum_val % (*as_map_entry));
                                        as_map_entry = bpf_map_lookup_elem(as_group_map, &as_action_ref);
                                        if (as_map_entry != NULL) {
                                            as_action_ref = *as_map_entry;
                                        } else {
                                            /* Not found, probably bug. Skip further execution of the extern. */
                                            return XDP_ABORTED;
                                        }
                                    } else {
                                        as_group_state = 1;
                                    }
                                } else {
                                    return XDP_ABORTED;
                                }
                            } else {
                                return XDP_ABORTED;
                            }
                        }
                        if (as_group_state == 0) {
                            as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_actions, &as_action_ref);
                        } else if (as_group_state == 1) {
                            as_value = BPF_MAP_LOOKUP_ELEM(ingress_as_defaultActionGroup, &ebpf_zero);
                        }
                        if (as_value != NULL) {
                            switch (as_value->action) {
                                case INGRESS_AS_ACT_INGRESS_SET_NEXTHOP: 
                                    {
headers->ipv4.ttl = headers->ipv4.ttl + 255;
                                        headers->ethernet.src_addr = as_value->u.ingress_set_nexthop.smac;
                                        headers->ethernet.dst_addr = as_value->u.ingress_set_nexthop.dmac;
                                        headers->vlan_tag.vlan_id = as_value->u.ingress_set_nexthop.vlan_id;
                                    }
                                    break;
                                case 0: 
                                    {
                                    }
                                    break;
                                default:
                                    return XDP_ABORTED;
                            }
                            action_run = as_value->action;
                        } else {
                            hit_3 = 0;
                        }
                    } else {
                    }
                }
                switch (action_run) {
                    case INGRESS_TBL_ROUTING_ACT_INGRESS_SET_NEXTHOP:
                    {
if (headers->ipv4.ttl == 0) {
{
meta_5 = ostd;
                                meta_5.drop = true;
                                ostd = meta_5;
                            };
                            hasExited = true;
                        }
                    }
                    break;
                    default:
                    {
                    }
                    break;
                }            }

            if (hasExited) {
;            }

            else {
                {
                    /* construct key */
                    struct ingress_tbl_switching_key key = {};
                    key.field0 = headers->ethernet.dst_addr;
                    key.field1 = headers->vlan_tag.vlan_id;
                    /* value */
                    struct ingress_tbl_switching_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_switching, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_switching_defaultAction, &ebpf_zero);
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case INGRESS_TBL_SWITCHING_ACT_INGRESS_FORWARD: 
                                {
meta_6 = ostd;
                                    egress_port_1 = value->u.ingress_forward.output_port;
                                    meta_6.drop = false;
                                    meta_6.multicast_group = 0;
                                    meta_6.egress_port = egress_port_1;
                                    ostd = meta_6;
                                }
                                break;
                            case INGRESS_TBL_SWITCHING_ACT_INGRESS_BROADCAST: 
                                {
meta_7 = ostd;
                                    multicast_group_1 = value->u.ingress_broadcast.grp_id;
                                    meta_7.drop = false;
                                    meta_7.multicast_group = multicast_group_1;
                                    ostd = meta_7;
                                }
                                break;
                            case 0: 
                                {
                                }
                                break;
                            default:
                                return XDP_ABORTED;
                        }
                    } else {
                        return XDP_ABORTED;
                    }
                }
;
                                {
                    /* construct key */
                    struct ingress_tbl_acl_key key = {};
                    key.field0 = headers->ipv4.src_addr;
                    key.field1 = headers->ipv4.dst_addr;
                    key.field2 = headers->ipv4.protocol;
                    key.field3 = local_metadata->l4_sport;
                    key.field4 = local_metadata->l4_dport;
                    /* value */
                    struct ingress_tbl_acl_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_acl, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(ingress_tbl_acl_defaultAction, &ebpf_zero);
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case INGRESS_TBL_ACL_ACT_INGRESS_DROP: 
                                {
meta_4 = ostd;
                                    meta_4.drop = true;
                                    ostd = meta_4;
                                }
                                break;
                            case 0: 
                                {
                                }
                                break;
                            default:
                                return XDP_ABORTED;
                        }
                    } else {
                        return XDP_ABORTED;
                    }
                }
;
                if (ostd.drop) {
;                }

                else {
                    headers->bridged_meta.ebpf_valid = true;
                    headers->bridged_meta.ingress_port = (u32)standard_metadata.ingress_port;
                }
            }
        }
    }
    {

        u16 ck_1_state = 0;
{
if (local_metadata->send_mac_learn_msg) {
bpf_map_push_elem(&mac_learn_digest_0, &local_metadata->mac_learn_msg, BPF_EXIST);            }

                        {
                u16 ck_1_tmp = 0;
                ck_1_tmp = headers->ipv4.hdr_checksum;
                ck_1_state = csum16_sub(ck_1_state, ck_1_tmp);
            }
;
                        {
                u16 ck_1_tmp_0 = 0;
                ck_1_tmp_0 = (headers->ipv4.ttl << 8) | headers->ipv4.protocol;
                ck_1_state = csum16_add(ck_1_state, ck_1_tmp_0);
            }
;
            headers->ipv4.hdr_checksum = ((u16) (~ck_1_state));
            ;
            ;
            ;
            ;
            ;
            ;
        }

        if (ostd.clone || ostd.multicast_group != 0) {
            struct xdp2tc_metadata xdp2tc_md = {};
            xdp2tc_md.headers = *headers;
            xdp2tc_md.ostd = ostd;
            xdp2tc_md.packetOffsetInBits = ebpf_packetOffsetInBits;
                void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)((struct ethhdr *) eth + 1) > data_end) {
        return XDP_ABORTED;
    }
    xdp2tc_md.pkt_ether_type = eth->h_proto;
    eth->h_proto = bpf_htons(0x0800);
            int ret = bpf_xdp_adjust_head(skb, -(int)sizeof(struct xdp2tc_metadata));
            if (ret) {
                return XDP_ABORTED;
            }
                data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if (((char *) data + 14 + sizeof(struct xdp2tc_metadata)) > (char *) data_end) {
        return XDP_ABORTED;
    }
__builtin_memmove(data, data + sizeof(struct xdp2tc_metadata), 14);
__builtin_memcpy(data + 14, &xdp2tc_md, sizeof(struct xdp2tc_metadata));
            return XDP_PASS;
        }
        if (ostd.drop || ostd.resubmit) {
            return XDP_ABORTED;
        }
        int outHeaderLength = 0;
        if (headers->bridged_meta.ebpf_valid) {
            outHeaderLength += 32;
        }
        if (headers->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (headers->vlan_tag.ebpf_valid) {
            outHeaderLength += 32;
        }
        if (headers->ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (headers->tcp.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (headers->udp.ebpf_valid) {
            outHeaderLength += 64;
        }

        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_xdp_adjust_head(skb, -outHeaderOffset);
            if (returnCode) {
                return XDP_ABORTED;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (headers->bridged_meta.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return XDP_ABORTED;
            }
            
            headers->bridged_meta.ingress_port = htonl(headers->bridged_meta.ingress_port);
            ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
        if (headers->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return XDP_ABORTED;
            }
            
            headers->ethernet.dst_addr = htonll(headers->ethernet.dst_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.src_addr = htonll(headers->ethernet.src_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.ether_type = bpf_htons(headers->ethernet.ether_type);
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (headers->vlan_tag.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&headers->vlan_tag.pri))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&headers->vlan_tag.cfi))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            headers->vlan_tag.vlan_id = bpf_htons(headers->vlan_tag.vlan_id << 4);
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 4, 0, (ebpf_byte >> 4));
            ebpf_packetOffsetInBits += 12;

            headers->vlan_tag.eth_type = bpf_htons(headers->vlan_tag.eth_type);
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (headers->ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&headers->ipv4.ver_ihl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&headers->ipv4.diffserv))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            headers->ipv4.total_len = bpf_htons(headers->ipv4.total_len);
            ebpf_byte = ((char*)(&headers->ipv4.total_len))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.total_len))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->ipv4.identification = bpf_htons(headers->ipv4.identification);
            ebpf_byte = ((char*)(&headers->ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->ipv4.flags_offset = bpf_htons(headers->ipv4.flags_offset);
            ebpf_byte = ((char*)(&headers->ipv4.flags_offset))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.flags_offset))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&headers->ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&headers->ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            headers->ipv4.hdr_checksum = bpf_htons(headers->ipv4.hdr_checksum);
            ebpf_byte = ((char*)(&headers->ipv4.hdr_checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.hdr_checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->ipv4.src_addr = htonl(headers->ipv4.src_addr);
            ebpf_byte = ((char*)(&headers->ipv4.src_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.src_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.src_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.src_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            headers->ipv4.dst_addr = htonl(headers->ipv4.dst_addr);
            ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
        if (headers->tcp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return XDP_ABORTED;
            }
            
            headers->tcp.sport = bpf_htons(headers->tcp.sport);
            ebpf_byte = ((char*)(&headers->tcp.sport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.sport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->tcp.dport = bpf_htons(headers->tcp.dport);
            ebpf_byte = ((char*)(&headers->tcp.dport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.dport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->tcp.seq_no = htonl(headers->tcp.seq_no);
            ebpf_byte = ((char*)(&headers->tcp.seq_no))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.seq_no))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.seq_no))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.seq_no))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            headers->tcp.ack_no = htonl(headers->tcp.ack_no);
            ebpf_byte = ((char*)(&headers->tcp.ack_no))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.ack_no))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.ack_no))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.ack_no))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            ebpf_byte = ((char*)(&headers->tcp.data_offset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&headers->tcp.res))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 1, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&headers->tcp.ecn))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 7));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 7, 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&headers->tcp.ctrl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 6;

            headers->tcp.window = bpf_htons(headers->tcp.window);
            ebpf_byte = ((char*)(&headers->tcp.window))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.window))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->tcp.checksum = bpf_htons(headers->tcp.checksum);
            ebpf_byte = ((char*)(&headers->tcp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->tcp.urgent_ptr = bpf_htons(headers->tcp.urgent_ptr);
            ebpf_byte = ((char*)(&headers->tcp.urgent_ptr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->tcp.urgent_ptr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (headers->udp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
                return XDP_ABORTED;
            }
            
            headers->udp.sport = bpf_htons(headers->udp.sport);
            ebpf_byte = ((char*)(&headers->udp.sport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->udp.sport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->udp.dport = bpf_htons(headers->udp.dport);
            ebpf_byte = ((char*)(&headers->udp.dport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->udp.dport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->udp.len = bpf_htons(headers->udp.len);
            ebpf_byte = ((char*)(&headers->udp.len))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->udp.len))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            headers->udp.checksum = bpf_htons(headers->udp.checksum);
            ebpf_byte = ((char*)(&headers->udp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->udp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }

    }
    return bpf_redirect_map(&tx_port, ostd.egress_port%DEVMAP_SIZE, 0);
}

SEC("xdp_devmap/xdp-egress")
int xdp_egress_func(struct xdp_md *skb) {
    struct local_metadata_t *local_metadata;

    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->data_end - skb->data;

    struct hdr_md *hdrMd;
    struct headers_t *headers;
    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_one);
    if (!hdrMd)
        return XDP_DROP;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    headers = &(hdrMd->cpumap_hdr);
    local_metadata = &(hdrMd->cpumap_usermeta);
    struct psa_egress_output_metadata_t ostd = {
       .clone = false,
            .drop = false,
        };

    struct psa_egress_input_metadata_t istd = {
            .class_of_service = 0,
            .egress_port = skb->egress_ifindex,
            .packet_path = 0,
            .instance = 0,
            .parser_error = ebpf_errorCode,
        };
    if (istd.egress_port == PSA_PORT_RECIRCULATE) {
        istd.egress_port = P4C_PSA_PORT_RECIRCULATE;
    }
    start: {
/* extract(headers->bridged_meta) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->bridged_meta.ingress_port = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->bridged_meta.ebpf_valid = 1;

/* extract(headers->ethernet) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->ethernet.dst_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.src_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.ether_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ethernet.ebpf_valid = 1;

        switch (headers->ethernet.ether_type) {
            case 33024: goto parse_vlan;
            default: goto accept;
        }
    }
    parse_vlan: {
/* extract(headers->vlan_tag) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->vlan_tag.pri = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers->vlan_tag.cfi = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        headers->vlan_tag.vlan_id = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 12));
        ebpf_packetOffsetInBits += 12;

        headers->vlan_tag.eth_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->vlan_tag.ebpf_valid = 1;

        goto accept;
    }

    reject: {
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }

    accept:
    istd.parser_error = ebpf_errorCode;

    {

        u8 hit_4;
        struct psa_egress_output_metadata_t meta_0;
        __builtin_memset((void *) &meta_0, 0, sizeof(struct psa_egress_output_metadata_t ));
        {
if (istd.packet_path == 2 && istd.egress_port == headers->bridged_meta.ingress_port) {
{
meta_0 = ostd;
                    meta_0.drop = true;
                    ostd = meta_0;
                };            }

            if (ostd.drop) {
;            }

            else {
                {
                    /* construct key */
                    struct egress_tbl_vlan_egress_key key = {};
                    key.field0 = istd.egress_port;
                    /* value */
                    struct egress_tbl_vlan_egress_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(egress_tbl_vlan_egress, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_4 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(egress_tbl_vlan_egress_defaultAction, &ebpf_zero);
                    } else {
                        hit_4 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_STRIP_VLAN: 
                                {
headers->ethernet.ether_type = headers->vlan_tag.eth_type;
                                                                        headers->vlan_tag.ebpf_valid = false;
                                                                        __sync_fetch_and_add(&(value->egress_out_pkts.bytes), pkt_len);
                                    __sync_fetch_and_add(&(value->egress_out_pkts.packets), 1);
;
                                }
                                break;
                            case EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_MOD_VLAN: 
                                {
headers->vlan_tag.vlan_id = value->u.egress_mod_vlan.vlan_id;
                                                                        __sync_fetch_and_add(&(value->egress_out_pkts.bytes), pkt_len);
                                    __sync_fetch_and_add(&(value->egress_out_pkts.packets), 1);
;
                                }
                                break;
                            case 0: 
                                {
                                }
                                break;
                            default:
                                return XDP_ABORTED;
                        }
                    } else {
                        return XDP_ABORTED;
                    }
                }
;            }

        }
    }
    {
{
;
            ;
        }

    return XDP_DROP;

        if (ostd.drop) {
            return XDP_ABORTED;
        }
        int outHeaderLength = 0;
        if (headers->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (headers->vlan_tag.ebpf_valid) {
            outHeaderLength += 32;
        }

        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_xdp_adjust_head(skb, -outHeaderOffset);
            if (returnCode) {
                return XDP_ABORTED;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (headers->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return XDP_ABORTED;
            }
            
            headers->ethernet.dst_addr = htonll(headers->ethernet.dst_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.src_addr = htonll(headers->ethernet.src_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.ether_type = bpf_htons(headers->ethernet.ether_type);
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (headers->vlan_tag.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&headers->vlan_tag.pri))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&headers->vlan_tag.cfi))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            headers->vlan_tag.vlan_id = bpf_htons(headers->vlan_tag.vlan_id << 4);
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 4, 0, (ebpf_byte >> 4));
            ebpf_packetOffsetInBits += 12;

            headers->vlan_tag.eth_type = bpf_htons(headers->vlan_tag.eth_type);
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }

    }

    if (ostd.clone || ostd.drop) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp_redirect_dummy_sec")
int xdp_redirect_dummy(struct xdp_md *skb) {
    return XDP_PASS;
}

SEC("classifier/tc-ingress")
int tc_ingress_func(SK_BUFF *skb) {
        unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;
        void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (((char *) data + 14 + sizeof(struct xdp2tc_metadata)) > (char *) data_end) {
        return TC_ACT_SHOT;
    }
    struct xdp2tc_metadata xdp2tc_md = {};
    bpf_skb_load_bytes(skb, 14, &xdp2tc_md, sizeof(struct xdp2tc_metadata));
        __u16 *ether_type = (__u16 *) ((void *) (long)skb->data + 12);
    if ((void *) ((__u16 *) ether_type + 1) >     (void *) (long) skb->data_end) {
        return TC_ACT_SHOT;
    }
    *ether_type = xdp2tc_md.pkt_ether_type;
    struct psa_ingress_output_metadata_t ostd = xdp2tc_md.ostd;
        struct headers_t *headers;
    headers = &(xdp2tc_md.headers);
    ebpf_packetOffsetInBits = xdp2tc_md.packetOffsetInBits;
    int ret = bpf_skb_adjust_room(skb, -(int)sizeof(struct xdp2tc_metadata), 1, 0);
    if (ret) {
        return XDP_ABORTED;
    }
        u16 ck_1_state_0 = 0;

if (ostd.clone) {
        do_packet_clones(skb, &clone_session_tbl, ostd.clone_session_id, CLONE_I2E, 1);
    }
    int outHeaderLength = 0;
    if (headers->bridged_meta.ebpf_valid) {
        outHeaderLength += 32;
    }
    if (headers->ethernet.ebpf_valid) {
        outHeaderLength += 112;
    }
    if (headers->vlan_tag.ebpf_valid) {
        outHeaderLength += 32;
    }
    if (headers->ipv4.ebpf_valid) {
        outHeaderLength += 160;
    }
    if (headers->tcp.ebpf_valid) {
        outHeaderLength += 160;
    }
    if (headers->udp.ebpf_valid) {
        outHeaderLength += 64;
    }

    int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
    if (outHeaderOffset != 0) {
        int returnCode = 0;
        returnCode = bpf_skb_adjust_room(skb, outHeaderOffset, 1, 0);
        if (returnCode) {
            return XDP_ABORTED;
        }
    }
    pkt = ((void*)(long)skb->data);
    ebpf_packetEnd = ((void*)(long)skb->data_end);
    ebpf_packetOffsetInBits = 0;
    if (headers->bridged_meta.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
            return XDP_ABORTED;
        }
        
        headers->bridged_meta.ingress_port = htonl(headers->bridged_meta.ingress_port);
        ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->bridged_meta.ingress_port))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

    }
    if (headers->ethernet.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
            return XDP_ABORTED;
        }
        
        headers->ethernet.dst_addr = htonll(headers->ethernet.dst_addr << 16);
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[4];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[5];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.src_addr = htonll(headers->ethernet.src_addr << 16);
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[4];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.src_addr))[5];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.ether_type = bpf_htons(headers->ethernet.ether_type);
        ebpf_byte = ((char*)(&headers->ethernet.ether_type))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ethernet.ether_type))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (headers->vlan_tag.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&headers->vlan_tag.pri))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&headers->vlan_tag.cfi))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        headers->vlan_tag.vlan_id = bpf_htons(headers->vlan_tag.vlan_id << 4);
        ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[1];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 4, 0, (ebpf_byte >> 4));
        ebpf_packetOffsetInBits += 12;

        headers->vlan_tag.eth_type = bpf_htons(headers->vlan_tag.eth_type);
        ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (headers->ipv4.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&headers->ipv4.ver_ihl))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        ebpf_byte = ((char*)(&headers->ipv4.diffserv))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.total_len = bpf_htons(headers->ipv4.total_len);
        ebpf_byte = ((char*)(&headers->ipv4.total_len))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.total_len))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.identification = bpf_htons(headers->ipv4.identification);
        ebpf_byte = ((char*)(&headers->ipv4.identification))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.identification))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.flags_offset = bpf_htons(headers->ipv4.flags_offset);
        ebpf_byte = ((char*)(&headers->ipv4.flags_offset))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.flags_offset))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        ebpf_byte = ((char*)(&headers->ipv4.ttl))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        ebpf_byte = ((char*)(&headers->ipv4.protocol))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        headers->ipv4.hdr_checksum = bpf_htons(headers->ipv4.hdr_checksum);
        ebpf_byte = ((char*)(&headers->ipv4.hdr_checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.hdr_checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->ipv4.src_addr = htonl(headers->ipv4.src_addr);
        ebpf_byte = ((char*)(&headers->ipv4.src_addr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.src_addr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.src_addr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.src_addr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        headers->ipv4.dst_addr = htonl(headers->ipv4.dst_addr);
        ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->ipv4.dst_addr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

    }
    if (headers->tcp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            return XDP_ABORTED;
        }
        
        headers->tcp.sport = bpf_htons(headers->tcp.sport);
        ebpf_byte = ((char*)(&headers->tcp.sport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.sport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.dport = bpf_htons(headers->tcp.dport);
        ebpf_byte = ((char*)(&headers->tcp.dport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.dport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.seq_no = htonl(headers->tcp.seq_no);
        ebpf_byte = ((char*)(&headers->tcp.seq_no))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.seq_no))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.seq_no))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.seq_no))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        headers->tcp.ack_no = htonl(headers->tcp.ack_no);
        ebpf_byte = ((char*)(&headers->tcp.ack_no))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.ack_no))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.ack_no))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.ack_no))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        ebpf_byte = ((char*)(&headers->tcp.data_offset))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&headers->tcp.res))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 1, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&headers->tcp.ecn))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 7));
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 7, 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&headers->tcp.ctrl))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 6;

        headers->tcp.window = bpf_htons(headers->tcp.window);
        ebpf_byte = ((char*)(&headers->tcp.window))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.window))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.checksum = bpf_htons(headers->tcp.checksum);
        ebpf_byte = ((char*)(&headers->tcp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->tcp.urgent_ptr = bpf_htons(headers->tcp.urgent_ptr);
        ebpf_byte = ((char*)(&headers->tcp.urgent_ptr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->tcp.urgent_ptr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (headers->udp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
            return XDP_ABORTED;
        }
        
        headers->udp.sport = bpf_htons(headers->udp.sport);
        ebpf_byte = ((char*)(&headers->udp.sport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->udp.sport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->udp.dport = bpf_htons(headers->udp.dport);
        ebpf_byte = ((char*)(&headers->udp.dport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->udp.dport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->udp.len = bpf_htons(headers->udp.len);
        ebpf_byte = ((char*)(&headers->udp.len))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->udp.len))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        headers->udp.checksum = bpf_htons(headers->udp.checksum);
        ebpf_byte = ((char*)(&headers->udp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&headers->udp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }

    if (ostd.multicast_group != 0) {
        do_packet_clones(skb, &multicast_grp_tbl, ostd.multicast_group, NORMAL_MULTICAST, 2);
        return TC_ACT_SHOT;
    }
    skb->priority = ostd.class_of_service;
    return bpf_redirect(ostd.egress_port, 0);    }

SEC("classifier/tc-egress")
int tc_egress_func(SK_BUFF *skb) {
    struct psa_global_metadata *compiler_meta__ = (struct psa_global_metadata *) skb->cb;
    unsigned ebpf_packetOffsetInBits = 0;
    unsigned ebpf_packetOffsetInBits_save = 0;
    ParserError_t ebpf_errorCode = NoError;
    void* pkt = ((void*)(long)skb->data);
    void* ebpf_packetEnd = ((void*)(long)skb->data_end);
    u32 ebpf_zero = 0;
    u32 ebpf_one = 1;
    unsigned char ebpf_byte;
    u32 pkt_len = skb->len;
    struct local_metadata_t *local_metadata;
    struct hdr_md *hdrMd;
    struct headers_t *headers;    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_one);
    if (!hdrMd)
        return TC_ACT_SHOT;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    headers = &(hdrMd->cpumap_hdr);
    local_metadata = &(hdrMd->cpumap_usermeta);
    struct psa_egress_output_metadata_t ostd = {
       .clone = false,
            .drop = false,
        };

    struct psa_egress_input_metadata_t istd = {
            .class_of_service = skb->priority,
            .egress_port = skb->ifindex,
            .packet_path = compiler_meta__->packet_path,
            .instance = compiler_meta__->instance,
            .parser_error = ebpf_errorCode,
        };
    if (istd.egress_port == PSA_PORT_RECIRCULATE) {
        istd.egress_port = P4C_PSA_PORT_RECIRCULATE;
    }
    start: {
/* extract(headers->bridged_meta) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->bridged_meta.ingress_port = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        headers->bridged_meta.ebpf_valid = 1;

/* extract(headers->ethernet) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->ethernet.dst_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.src_addr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        headers->ethernet.ether_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->ethernet.ebpf_valid = 1;

        switch (headers->ethernet.ether_type) {
            case 33024: goto parse_vlan;
            default: goto accept;
        }
    }
    parse_vlan: {
/* extract(headers->vlan_tag) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        headers->vlan_tag.pri = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        headers->vlan_tag.cfi = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        headers->vlan_tag.vlan_id = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 12));
        ebpf_packetOffsetInBits += 12;

        headers->vlan_tag.eth_type = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        headers->vlan_tag.ebpf_valid = 1;

        goto accept;
    }

    reject: {
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }

    accept:
    istd.parser_error = ebpf_errorCode;
    {
        u8 hit_5;
        struct psa_egress_output_metadata_t meta_0;
        __builtin_memset((void *) &meta_0, 0, sizeof(struct psa_egress_output_metadata_t ));
        {
if (istd.packet_path == 2 && istd.egress_port == headers->bridged_meta.ingress_port) {
{
meta_0 = ostd;
                    meta_0.drop = true;
                    ostd = meta_0;
                };            }

            if (ostd.drop) {
;            }

            else {
                {
                    /* construct key */
                    struct egress_tbl_vlan_egress_key key = {};
                    key.field0 = istd.egress_port;
                    /* value */
                    struct egress_tbl_vlan_egress_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(egress_tbl_vlan_egress, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_5 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(egress_tbl_vlan_egress_defaultAction, &ebpf_zero);
                    } else {
                        hit_5 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_STRIP_VLAN: 
                                {
headers->ethernet.ether_type = headers->vlan_tag.eth_type;
                                                                        headers->vlan_tag.ebpf_valid = false;
                                                                        __sync_fetch_and_add(&(value->egress_out_pkts.bytes), pkt_len);
                                    __sync_fetch_and_add(&(value->egress_out_pkts.packets), 1);
;
                                }
                                break;
                            case EGRESS_TBL_VLAN_EGRESS_ACT_EGRESS_MOD_VLAN: 
                                {
headers->vlan_tag.vlan_id = value->u.egress_mod_vlan.vlan_id;
                                                                        __sync_fetch_and_add(&(value->egress_out_pkts.bytes), pkt_len);
                                    __sync_fetch_and_add(&(value->egress_out_pkts.packets), 1);
;
                                }
                                break;
                            case 0: 
                                {
                                }
                                break;
                            default:
                                return XDP_ABORTED;
                        }
                    } else {
                        return XDP_ABORTED;
                    }
                }
;            }

        }
    }
    {
{
;
            ;
        }

        int outHeaderLength = 0;
        if (headers->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (headers->vlan_tag.ebpf_valid) {
            outHeaderLength += 32;
        }

        int outHeaderOffset = BYTES(outHeaderLength) - BYTES(ebpf_packetOffsetInBits);
        if (outHeaderOffset != 0) {
            int returnCode = 0;
            returnCode = bpf_skb_adjust_room(skb, outHeaderOffset, 1, 0);
            if (returnCode) {
                return XDP_ABORTED;
            }
        }
        pkt = ((void*)(long)skb->data);
        ebpf_packetEnd = ((void*)(long)skb->data_end);
        ebpf_packetOffsetInBits = 0;
        if (headers->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return XDP_ABORTED;
            }
            
            headers->ethernet.dst_addr = htonll(headers->ethernet.dst_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.dst_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.src_addr = htonll(headers->ethernet.src_addr << 16);
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.src_addr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            headers->ethernet.ether_type = bpf_htons(headers->ethernet.ether_type);
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->ethernet.ether_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (headers->vlan_tag.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 32)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&headers->vlan_tag.pri))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&headers->vlan_tag.cfi))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            headers->vlan_tag.vlan_id = bpf_htons(headers->vlan_tag.vlan_id << 4);
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 4));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 4, 4, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.vlan_id))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 4, 0, (ebpf_byte >> 4));
            ebpf_packetOffsetInBits += 12;

            headers->vlan_tag.eth_type = bpf_htons(headers->vlan_tag.eth_type);
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&headers->vlan_tag.eth_type))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }

    }
    if (ostd.clone) {
        do_packet_clones(skb, &clone_session_tbl, ostd.clone_session_id, CLONE_E2E, 3);
    }

    if (ostd.drop) {
        return TC_ACT_SHOT;;
    }

    if (istd.egress_port == P4C_PSA_PORT_RECIRCULATE) {
        compiler_meta__->packet_path = RECIRCULATE;
        return bpf_redirect(PSA_PORT_RECIRCULATE, BPF_F_INGRESS);
    }

    
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
