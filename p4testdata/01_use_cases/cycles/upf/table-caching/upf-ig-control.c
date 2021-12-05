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


struct ethernet_t {
    u64 dstAddr; /* macAddr_t */
    u64 srcAddr; /* macAddr_t */
    u16 etherType; /* bit<16> */
    u8 ebpf_valid;
};
struct ipv4_t {
    u8 version; /* bit<4> */
    u8 ihl; /* bit<4> */
    u8 dscp; /* bit<6> */
    u8 ecn; /* bit<2> */
    u16 totalLen; /* bit<16> */
    u16 identification; /* bit<16> */
    u8 flags; /* bit<3> */
    u16 fragOffset; /* bit<13> */
    u8 ttl; /* bit<8> */
    u8 protocol; /* bit<8> */
    u16 hdrChecksum; /* bit<16> */
    u32 srcAddr; /* ip4Addr_t */
    u32 dstAddr; /* ip4Addr_t */
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
struct icmp_t {
    u8 icmp_type; /* bit<8> */
    u8 icmp_code; /* bit<8> */
    u16 checksum; /* bit<16> */
    u16 identifier; /* bit<16> */
    u16 sequence_number; /* bit<16> */
    u64 timestamp; /* bit<64> */
    u8 ebpf_valid;
};
struct gtpu_t {
    u8 version; /* bit<3> */
    u8 pt; /* bit<1> */
    u8 spare; /* bit<1> */
    u8 ex_flag; /* bit<1> */
    u8 seq_flag; /* bit<1> */
    u8 npdu_flag; /* bit<1> */
    u8 msgtype; /* bit<8> */
    u16 msglen; /* bit<16> */
    u32 teid; /* bit<32> */
    u8 ebpf_valid;
};
struct upf_meta_t {
    u64 seid; /* bit<64> */
    u32 far_id; /* bit<32> */
    u8 src; /* destination_t */
    u8 dest; /* destination_t */
    u32 outer_dst_addr; /* ip4Addr_t */
    u16 l4_sport; /* bit<16> */
    u16 l4_dport; /* bit<16> */
    u8 src_port_range_id; /* bit<8> */
    u8 dst_port_range_id; /* bit<8> */
    u16 ipv4_len; /* bit<16> */
    u32 teid; /* bit<32> */
    u32 gtpu_remote_ip; /* bit<32> */
    u32 gtpu_local_ip; /* bit<32> */
};
struct metadata {
    struct upf_meta_t upf; /* upf_meta_t */
};
struct headers {
    struct ethernet_t ethernet; /* ethernet_t */
    struct ipv4_t gtpu_ipv4; /* ipv4_t */
    struct udp_t gtpu_udp; /* udp_t */
    struct gtpu_t gtpu; /* gtpu_t */
    struct ipv4_t inner_ipv4; /* ipv4_t */
    struct udp_t inner_udp; /* udp_t */
    struct ipv4_t ipv4; /* ipv4_t */
    struct tcp_t tcp; /* tcp_t */
    struct udp_t udp; /* udp_t */
    struct icmp_t icmp; /* icmp_t */
__u32 __helper_variable;
};
struct empty_t {
};
struct tuple_0 {
    u8 f0; /* bit<8> */
    u8 f1; /* bit<8> */
};
struct tuple_1 {
    u8 f0; /* bit<4> */
    u8 f1; /* bit<4> */
    u8 f2; /* bit<6> */
    u8 f3; /* bit<2> */
    u16 f4; /* bit<16> */
    u16 f5; /* bit<16> */
    u8 f6; /* bit<3> */
    u16 f7; /* bit<13> */
    u8 f8; /* bit<8> */
    u8 f9; /* bit<8> */
    u32 f10; /* bit<32> */
    u32 f11; /* bit<32> */
};
struct hdr_md {
    struct headers cpumap_hdr;
    struct metadata cpumap_usermeta;
    __u8 __hook;
};
struct xdp2tc_metadata {
    struct headers headers;
    struct psa_ingress_output_metadata_t ostd;
    __u32 packetOffsetInBits;
    __u16 pkt_ether_type;
} __attribute__((aligned(4)));


struct ingress_ip_forward_ipv4_lpm_key {
    u32 prefixlen;
    u8 field0; /* meta.upf.dest */
    u32 field1; /* meta.upf.outer_dst_addr */
} __attribute__((aligned(4)));
#define INGRESS_IP_FORWARD_IPV4_LPM_ACT_INGRESS_IP_FORWARD_FORWARD 1
#define INGRESS_IP_FORWARD_IPV4_LPM_ACT_INGRESS_IP_FORWARD_DROP 2
struct ingress_ip_forward_ipv4_lpm_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u64 srcAddr;
            u64 dstAddr;
            u32 port;
        } ingress_ip_forward_forward;
        struct {
        } ingress_ip_forward_drop;
    } u;
};
struct ingress_ip_forward_ipv4_lpm_value_cache {
    struct ingress_ip_forward_ipv4_lpm_value value;
    u8 hit;
};
struct ingress_upf_ingress_far_lookup_key {
    u32 field0; /* meta.upf.far_id */
} __attribute__((aligned(4)));
#define INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_FAR_FORWARD 1
#define INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_FAR_ENCAP_FORWARD 2
#define INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP 3
struct ingress_upf_ingress_far_lookup_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u8 dest;
        } ingress_upf_ingress_far_forward;
        struct {
            u8 dest;
            u32 teid;
            u32 gtpu_remote_ip;
            u32 gtpu_local_ip;
        } ingress_upf_ingress_far_encap_forward;
        struct {
        } ingress_upf_ingress_drop;
    } u;
};
struct ingress_upf_ingress_pdr_lookup_key {
    u64 field0; /* meta.upf.seid */
    u32 field1; /* hdr.ipv4.srcAddr */
    u32 field2; /* hdr.ipv4.dstAddr */
    u8 field3; /* hdr.ipv4.protocol */
    u8 field4; /* meta.upf.src_port_range_id */
    u8 field5; /* meta.upf.dst_port_range_id */
    u8 field6; /* meta.upf.src */
} __attribute__((aligned(8)));
#define MAX_INGRESS_UPF_INGRESS_PDR_LOOKUP_KEY_MASKS 3
struct ingress_upf_ingress_pdr_lookup_key_mask {
    __u8 mask[sizeof(struct ingress_upf_ingress_pdr_lookup_key)];
} __attribute__((aligned(8)));
#define INGRESS_UPF_INGRESS_PDR_LOOKUP_ACT_INGRESS_UPF_INGRESS_SET_FAR_ID 1
#define INGRESS_UPF_INGRESS_PDR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP 2
struct ingress_upf_ingress_pdr_lookup_value {
    unsigned int action;
    __u32 priority;
    union {
        struct {
        } _NoAction;
        struct {
            u32 far_id;
        } ingress_upf_ingress_set_far_id;
        struct {
        } ingress_upf_ingress_drop;
    } u;
};
struct ingress_upf_ingress_pdr_lookup_value_mask {
    __u32 tuple_id;
    struct ingress_upf_ingress_pdr_lookup_key_mask next_tuple_mask;
    __u8 has_next;
};
struct ingress_upf_ingress_pdr_lookup_value_cache {
    struct ingress_upf_ingress_pdr_lookup_value value;
    u8 hit;
};
struct ingress_upf_ingress_session_lookup_by_teid_key {
    u32 field0; /* hdr.gtpu.teid */
} __attribute__((aligned(4)));
#define INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_TEID_ACT_INGRESS_UPF_INGRESS_SET_SEID 1
#define INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_TEID_ACT__NOP 2
struct ingress_upf_ingress_session_lookup_by_teid_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u64 seid;
        } ingress_upf_ingress_set_seid;
        struct {
        } _nop;
    } u;
};
struct ingress_upf_ingress_session_lookup_by_ue_ip_key {
    u32 field0; /* hdr.ipv4.dstAddr */
} __attribute__((aligned(4)));
#define INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_UE_IP_ACT_INGRESS_UPF_INGRESS_SET_SEID 1
#define INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_UE_IP_ACT__NOP 2
struct ingress_upf_ingress_session_lookup_by_ue_ip_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u64 seid;
        } ingress_upf_ingress_set_seid;
        struct {
        } _nop;
    } u;
};
struct ingress_upf_ingress_source_interface_lookup_by_port_key {
    u32 field0; /* istd.ingress_port */
} __attribute__((aligned(4)));
#define INGRESS_UPF_INGRESS_SOURCE_INTERFACE_LOOKUP_BY_PORT_ACT_INGRESS_UPF_INGRESS_SET_SOURCE_INTERFACE 1
#define INGRESS_UPF_INGRESS_SOURCE_INTERFACE_LOOKUP_BY_PORT_ACT__NOP 2
struct ingress_upf_ingress_source_interface_lookup_by_port_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
            u8 src;
        } ingress_upf_ingress_set_source_interface;
        struct {
        } _nop;
    } u;
};
struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_key {
    u16 field0; /* meta.upf.l4_dport */
} __attribute__((aligned(4)));
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_DST_PORT_ACT__NOP 1
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_DST_PORT_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_DST_PORT_RANGE_ID 2
struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } _nop;
        struct {
            u8 range_id;
        } ingress_upf_process_ingress_l4port_set_ingress_dst_port_range_id;
    } u;
};
struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_key {
    u16 field0; /* meta.upf.l4_sport */
} __attribute__((aligned(4)));
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_SRC_PORT_ACT__NOP 1
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_SRC_PORT_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_SRC_PORT_RANGE_ID 2
struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } _nop;
        struct {
            u8 range_id;
        } ingress_upf_process_ingress_l4port_set_ingress_src_port_range_id;
    } u;
};
struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key {
    u8 field0; /*     hdr.tcp.ebpf_valid */
    u8 field1; /*     hdr.udp.ebpf_valid */
} __attribute__((aligned(4)));
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT__NOP 1
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_TCP_PORT_FIELDS 2
#define INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_UDP_PORT_FIELDS 3
struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value {
    unsigned int action;
    union {
        struct {
        } _NoAction;
        struct {
        } _nop;
        struct {
        } ingress_upf_process_ingress_l4port_set_ingress_tcp_port_fields;
        struct {
        } ingress_upf_process_ingress_l4port_set_ingress_udp_port_fields;
    } u;
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
REGISTER_TABLE_FLAGS(ingress_ip_forward_ipv4_lpm, BPF_MAP_TYPE_LPM_TRIE, struct ingress_ip_forward_ipv4_lpm_key, struct ingress_ip_forward_ipv4_lpm_value, 1024, BPF_F_NO_PREALLOC)
BPF_ANNOTATE_KV_PAIR(ingress_ip_forward_ipv4_lpm, struct ingress_ip_forward_ipv4_lpm_key, struct ingress_ip_forward_ipv4_lpm_value)
REGISTER_TABLE(ingress_ip_forward_ipv4_lpm_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_ip_forward_ipv4_lpm_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_ip_forward_ipv4_lpm_defaultAction, u32, struct ingress_ip_forward_ipv4_lpm_value)
REGISTER_TABLE(ingress_ip_forward_ipv4_lpm_cache, BPF_MAP_TYPE_LRU_HASH, struct ingress_ip_forward_ipv4_lpm_key, struct ingress_ip_forward_ipv4_lpm_value_cache, 512)
BPF_ANNOTATE_KV_PAIR(ingress_ip_forward_ipv4_lpm_cache, struct ingress_ip_forward_ipv4_lpm_key, struct ingress_ip_forward_ipv4_lpm_value_cache)
REGISTER_TABLE(ingress_upf_ingress_far_lookup, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_far_lookup_key, struct ingress_upf_ingress_far_lookup_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_far_lookup, struct ingress_upf_ingress_far_lookup_key, struct ingress_upf_ingress_far_lookup_value)
REGISTER_TABLE(ingress_upf_ingress_far_lookup_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_ingress_far_lookup_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_far_lookup_defaultAction, u32, struct ingress_upf_ingress_far_lookup_value)
REGISTER_TABLE(ingress_upf_ingress_pdr_lookup_prefixes, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_pdr_lookup_key_mask, struct ingress_upf_ingress_pdr_lookup_value_mask, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_pdr_lookup_prefixes, struct ingress_upf_ingress_pdr_lookup_key_mask, struct ingress_upf_ingress_pdr_lookup_value_mask)
REGISTER_TABLE_INNER(ingress_upf_ingress_pdr_lookup_tuple, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_pdr_lookup_key, struct ingress_upf_ingress_pdr_lookup_value, 1024, 3, 3)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_pdr_lookup_tuple, struct ingress_upf_ingress_pdr_lookup_key, struct ingress_upf_ingress_pdr_lookup_value)
REGISTER_TABLE_OUTER(ingress_upf_ingress_pdr_lookup_tuples_map, BPF_MAP_TYPE_ARRAY_OF_MAPS, __u32, __u32, 1024, 3, ingress_upf_ingress_pdr_lookup_tuple)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_pdr_lookup_tuples_map, __u32, __u32)
REGISTER_TABLE(ingress_upf_ingress_pdr_lookup_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_ingress_pdr_lookup_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_pdr_lookup_defaultAction, u32, struct ingress_upf_ingress_pdr_lookup_value)
REGISTER_TABLE(ingress_upf_ingress_pdr_lookup_cache, BPF_MAP_TYPE_LRU_HASH, struct ingress_upf_ingress_pdr_lookup_key, struct ingress_upf_ingress_pdr_lookup_value_cache, 512)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_pdr_lookup_cache, struct ingress_upf_ingress_pdr_lookup_key, struct ingress_upf_ingress_pdr_lookup_value_cache)
REGISTER_TABLE(ingress_upf_ingress_session_lookup_by_teid, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_session_lookup_by_teid_key, struct ingress_upf_ingress_session_lookup_by_teid_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_session_lookup_by_teid, struct ingress_upf_ingress_session_lookup_by_teid_key, struct ingress_upf_ingress_session_lookup_by_teid_value)
REGISTER_TABLE(ingress_upf_ingress_session_lookup_by_teid_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_ingress_session_lookup_by_teid_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_session_lookup_by_teid_defaultAction, u32, struct ingress_upf_ingress_session_lookup_by_teid_value)
REGISTER_TABLE(ingress_upf_ingress_session_lookup_by_ue_ip, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_session_lookup_by_ue_ip_key, struct ingress_upf_ingress_session_lookup_by_ue_ip_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_session_lookup_by_ue_ip, struct ingress_upf_ingress_session_lookup_by_ue_ip_key, struct ingress_upf_ingress_session_lookup_by_ue_ip_value)
REGISTER_TABLE(ingress_upf_ingress_session_lookup_by_ue_ip_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_ingress_session_lookup_by_ue_ip_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_session_lookup_by_ue_ip_defaultAction, u32, struct ingress_upf_ingress_session_lookup_by_ue_ip_value)
REGISTER_TABLE(ingress_upf_ingress_source_interface_lookup_by_port, BPF_MAP_TYPE_HASH, struct ingress_upf_ingress_source_interface_lookup_by_port_key, struct ingress_upf_ingress_source_interface_lookup_by_port_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_source_interface_lookup_by_port, struct ingress_upf_ingress_source_interface_lookup_by_port_key, struct ingress_upf_ingress_source_interface_lookup_by_port_value)
REGISTER_TABLE(ingress_upf_ingress_source_interface_lookup_by_port_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_ingress_source_interface_lookup_by_port_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_ingress_source_interface_lookup_by_port_defaultAction, u32, struct ingress_upf_ingress_source_interface_lookup_by_port_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4_dst_port, BPF_MAP_TYPE_HASH, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_key, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value, 512)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4_dst_port, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_key, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4_dst_port_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4_dst_port_defaultAction, u32, struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4_src_port, BPF_MAP_TYPE_HASH, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_key, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value, 512)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4_src_port, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_key, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4_src_port_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4_src_port_defaultAction, u32, struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4port_fields, BPF_MAP_TYPE_HASH, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value, 1024)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4port_fields, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value)
REGISTER_TABLE(ingress_upf_process_ingress_l4port_ingress_l4port_fields_defaultAction, BPF_MAP_TYPE_ARRAY, u32, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value, 1)
BPF_ANNOTATE_KV_PAIR(ingress_upf_process_ingress_l4port_ingress_l4port_fields_defaultAction, u32, struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value)
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
    struct ingress_ip_forward_ipv4_lpm_value value_0 = {
        .action = INGRESS_IP_FORWARD_IPV4_LPM_ACT_INGRESS_IP_FORWARD_DROP,
        .u = {.ingress_ip_forward_drop = {}},
    };
    int ret = BPF_MAP_UPDATE_ELEM(ingress_ip_forward_ipv4_lpm_defaultAction, &ebpf_zero, &value_0, BPF_ANY);
    if (ret) {
    } else {
    }
    struct ingress_upf_ingress_far_lookup_value value_1 = {
        .action = INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP,
        .u = {.ingress_upf_ingress_drop = {}},
    };
    int ret_0 = BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_far_lookup_defaultAction, &ebpf_zero, &value_1, BPF_ANY);
    if (ret_0) {
    } else {
    }
    struct ingress_upf_ingress_pdr_lookup_value value_2 = {
        .action = INGRESS_UPF_INGRESS_PDR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP,
        .u = {.ingress_upf_ingress_drop = {}},
    };
    int ret_1 = BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_pdr_lookup_defaultAction, &ebpf_zero, &value_2, BPF_ANY);
    if (ret_1) {
    } else {
    }
    struct ingress_upf_ingress_session_lookup_by_teid_value value_3 = {
        .action = INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_TEID_ACT__NOP,
        .u = {._nop = {}},
    };
    int ret_2 = BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_session_lookup_by_teid_defaultAction, &ebpf_zero, &value_3, BPF_ANY);
    if (ret_2) {
    } else {
    }
    struct ingress_upf_ingress_session_lookup_by_ue_ip_value value_4 = {
        .action = INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_UE_IP_ACT__NOP,
        .u = {._nop = {}},
    };
    int ret_3 = BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_session_lookup_by_ue_ip_defaultAction, &ebpf_zero, &value_4, BPF_ANY);
    if (ret_3) {
    } else {
    }
    struct ingress_upf_ingress_source_interface_lookup_by_port_value value_5 = {
        .action = INGRESS_UPF_INGRESS_SOURCE_INTERFACE_LOOKUP_BY_PORT_ACT__NOP,
        .u = {._nop = {}},
    };
    int ret_4 = BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_source_interface_lookup_by_port_defaultAction, &ebpf_zero, &value_5, BPF_ANY);
    if (ret_4) {
    } else {
    }
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key key_0 = {};
    key_0.field0 = true;
    key_0.field1 = false;
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value value_6 = {
        .action = INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_TCP_PORT_FIELDS,
        .u = {.ingress_upf_process_ingress_l4port_set_ingress_tcp_port_fields = {}},
    };
    int ret_5 = BPF_MAP_UPDATE_ELEM(ingress_upf_process_ingress_l4port_ingress_l4port_fields, &key_0, &value_6, BPF_ANY);
    if (ret_5) {
    } else {
    }
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key key_1 = {};
    key_1.field0 = false;
    key_1.field1 = true;
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value value_7 = {
        .action = INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_UDP_PORT_FIELDS,
        .u = {.ingress_upf_process_ingress_l4port_set_ingress_udp_port_fields = {}},
    };
    int ret_6 = BPF_MAP_UPDATE_ELEM(ingress_upf_process_ingress_l4port_ingress_l4port_fields, &key_1, &value_7, BPF_ANY);
    if (ret_6) {
    } else {
    }
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key key_2 = {};
    key_2.field0 = false;
    key_2.field1 = false;
    struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value value_8 = {
        .action = INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT__NOP,
        .u = {._nop = {}},
    };
    int ret_7 = BPF_MAP_UPDATE_ELEM(ingress_upf_process_ingress_l4port_ingress_l4port_fields, &key_2, &value_8, BPF_ANY);
    if (ret_7) {
    } else {
    }

    return 0;
}

SEC("xdp_ingress/xdp-ingress")
int xdp_ingress_func(struct xdp_md *skb) {
    struct empty_t resubmit_meta;

    struct hdr_md *hdrMd;
    struct headers *hdr;
    struct metadata *meta;

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

    hdr = &(hdrMd->cpumap_hdr);
    meta = &(hdrMd->cpumap_usermeta);
    struct psa_ingress_output_metadata_t ostd = {
            .drop = true,
    };

    u16 ck_0_state = 0;
    start: {
/* extract(hdr->ethernet) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->ethernet.dstAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        hdr->ethernet.srcAddr = (u64)((load_dword(pkt, BYTES(ebpf_packetOffsetInBits)) >> 16) & EBPF_MASK(u64, 48));
        ebpf_packetOffsetInBits += 48;

        hdr->ethernet.etherType = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->ethernet.ebpf_valid = 1;

        switch (hdr->ethernet.etherType) {
            case 2048: goto parse_ipv4;
            default: goto accept;
        }
    }
    parse_ipv4: {
/* extract(hdr->ipv4) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->ipv4.version = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        hdr->ipv4.ihl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        hdr->ipv4.dscp = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 2) & EBPF_MASK(u8, 6));
        ebpf_packetOffsetInBits += 6;

        hdr->ipv4.ecn = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 2));
        ebpf_packetOffsetInBits += 2;

        hdr->ipv4.totalLen = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->ipv4.identification = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->ipv4.flags = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        hdr->ipv4.fragOffset = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
        ebpf_packetOffsetInBits += 13;

        hdr->ipv4.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        hdr->ipv4.protocol = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        hdr->ipv4.hdrChecksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->ipv4.srcAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->ipv4.dstAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->ipv4.ebpf_valid = 1;

/* ck_0.clear() */
        ck_0_state = 0;
/* ck_0.subtract(hdr->ipv4.hdrChecksum) */
        {
            u16 ck_0_tmp = 0;
            ck_0_tmp = hdr->ipv4.hdrChecksum;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp);
        }
/* ck_0.subtract(hdr->ipv4.ttl, hdr->ipv4.protocol) */
        {
            u16 ck_0_tmp_0 = 0;
            ck_0_tmp_0 = (hdr->ipv4.ttl << 8) | hdr->ipv4.protocol;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp_0);
        }
hdr->ipv4.hdrChecksum = /* ck_0.get() */
((u16) (~ck_0_state));        switch (hdr->ipv4.protocol) {
            case 17: goto parse_udp;
            case 6: goto parse_tcp;
            case 1: goto accept;
            default: goto noMatch;
        }
    }
    parse_udp: {
/* extract(hdr->udp) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->udp.sport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.dport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.len = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.ebpf_valid = 1;

        switch (hdr->udp.dport) {
            case 2152: goto parse_gtpu;
            default: goto accept;
        }
    }
    parse_tcp: {
/* extract(hdr->tcp) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->tcp.sport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.dport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.seq_no = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->tcp.ack_no = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->tcp.data_offset = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        hdr->tcp.res = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 1) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        hdr->tcp.ecn = (u8)((load_half(pkt, BYTES(ebpf_packetOffsetInBits)) >> 6) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        hdr->tcp.ctrl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 6));
        ebpf_packetOffsetInBits += 6;

        hdr->tcp.window = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.urgent_ptr = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.ebpf_valid = 1;

        goto accept;
    }
    parse_gtpu: {
/* extract(hdr->gtpu) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->gtpu.version = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        hdr->gtpu.pt = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        hdr->gtpu.spare = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 3) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        hdr->gtpu.ex_flag = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 2) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        hdr->gtpu.seq_flag = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 1) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        hdr->gtpu.npdu_flag = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 1));
        ebpf_packetOffsetInBits += 1;

        hdr->gtpu.msgtype = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        hdr->gtpu.msglen = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu.teid = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->gtpu.ebpf_valid = 1;

/* extract(hdr->inner_ipv4) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->inner_ipv4.version = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 4) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        hdr->inner_ipv4.ihl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 4));
        ebpf_packetOffsetInBits += 4;

        hdr->inner_ipv4.dscp = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 2) & EBPF_MASK(u8, 6));
        ebpf_packetOffsetInBits += 6;

        hdr->inner_ipv4.ecn = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u8, 2));
        ebpf_packetOffsetInBits += 2;

        hdr->inner_ipv4.totalLen = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_ipv4.identification = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_ipv4.flags = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits)) >> 5) & EBPF_MASK(u8, 3));
        ebpf_packetOffsetInBits += 3;

        hdr->inner_ipv4.fragOffset = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))) & EBPF_MASK(u16, 13));
        ebpf_packetOffsetInBits += 13;

        hdr->inner_ipv4.ttl = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        hdr->inner_ipv4.protocol = (u8)((load_byte(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 8;

        hdr->inner_ipv4.hdrChecksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_ipv4.srcAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->inner_ipv4.dstAddr = (u32)((load_word(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 32;

        hdr->inner_ipv4.ebpf_valid = 1;

/* ck_0.clear() */
        ck_0_state = 0;
/* ck_0.subtract(hdr->inner_ipv4.hdrChecksum) */
        {
            u16 ck_0_tmp_1 = 0;
            ck_0_tmp_1 = hdr->inner_ipv4.hdrChecksum;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp_1);
        }
/* ck_0.subtract(hdr->ipv4.ttl, hdr->ipv4.protocol) */
        {
            u16 ck_0_tmp_2 = 0;
            ck_0_tmp_2 = (hdr->ipv4.ttl << 8) | hdr->ipv4.protocol;
            ck_0_state = csum16_sub(ck_0_state, ck_0_tmp_2);
        }
hdr->inner_ipv4.hdrChecksum = /* ck_0.get() */
((u16) (~ck_0_state));        switch (hdr->inner_ipv4.protocol) {
            case 17: goto parse_inner_udp;
            case 6: goto parse_tcp;
            case 1: goto accept;
            default: goto noMatch;
        }
    }
    parse_inner_udp: {
/* extract(hdr->inner_udp) */
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64 + 0)) {
            ebpf_errorCode = PacketTooShort;
            goto reject;
        }

        hdr->inner_udp.sport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_udp.dport = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_udp.len = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_udp.checksum = (u16)((load_half(pkt, BYTES(ebpf_packetOffsetInBits))));
        ebpf_packetOffsetInBits += 16;

        hdr->inner_udp.ebpf_valid = 1;

        goto accept;
    }
    noMatch: {
/* verify(false, error.NoMatch) */
        if (!(false)) {
            ebpf_errorCode = NoMatch;
            goto reject;
        }
        goto reject;
    }

    reject: {
        if (ebpf_errorCode == 0) {
            return XDP_ABORTED;
        }
        goto accept;
    }


    accept: {
        struct psa_ingress_input_metadata_t istd = {
            .ingress_port = skb->ingress_ifindex,
            .packet_path = 0,
            .parser_error = ebpf_errorCode,
    };
        u8 hit_3;
        struct psa_ingress_output_metadata_t meta_2;
        __builtin_memset((void *) &meta_2, 0, sizeof(struct psa_ingress_output_metadata_t ));
        struct psa_ingress_output_metadata_t meta_3;
        __builtin_memset((void *) &meta_3, 0, sizeof(struct psa_ingress_output_metadata_t ));
        struct psa_ingress_output_metadata_t meta_4;
        __builtin_memset((void *) &meta_4, 0, sizeof(struct psa_ingress_output_metadata_t ));
        struct psa_ingress_output_metadata_t meta_7;
        __builtin_memset((void *) &meta_7, 0, sizeof(struct psa_ingress_output_metadata_t ));
        u32 egress_port_1;
        u8 upf_ingress_hasReturned;
        struct psa_ingress_output_metadata_t meta_0;
        __builtin_memset((void *) &meta_0, 0, sizeof(struct psa_ingress_output_metadata_t ));
        {
if (            hdr->gtpu.ebpf_valid) {
hdr->gtpu_ipv4 = hdr->ipv4;
                hdr->ipv4 = hdr->inner_ipv4;
                hdr->gtpu_udp = hdr->udp;
                if (                hdr->inner_udp.ebpf_valid) {
hdr->udp = hdr->inner_udp;                }

                else {
                    hdr->udp.ebpf_valid = false;                }

            }
                        {
                /* construct key */
                struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_key key = {};
                key.field0 =                 hdr->tcp.ebpf_valid;
                key.field1 =                 hdr->udp.ebpf_valid;
                /* value */
                struct ingress_upf_process_ingress_l4port_ingress_l4port_fields_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4port_fields, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4port_fields_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT__NOP: 
                            {
                            }
                            break;
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_TCP_PORT_FIELDS: 
                            {
meta->upf.l4_sport = hdr->tcp.sport;
                                meta->upf.l4_dport = hdr->tcp.dport;
                            }
                            break;
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4PORT_FIELDS_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_UDP_PORT_FIELDS: 
                            {
meta->upf.l4_sport = hdr->udp.sport;
                                meta->upf.l4_dport = hdr->udp.dport;
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
                struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_key key = {};
                key.field0 = meta->upf.l4_sport;
                /* value */
                struct ingress_upf_process_ingress_l4port_ingress_l4_src_port_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4_src_port, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4_src_port_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_SRC_PORT_ACT__NOP: 
                            {
                            }
                            break;
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_SRC_PORT_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_SRC_PORT_RANGE_ID: 
                            {
meta->upf.src_port_range_id = value->u.ingress_upf_process_ingress_l4port_set_ingress_src_port_range_id.range_id;
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
                struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_key key = {};
                key.field0 = meta->upf.l4_dport;
                /* value */
                struct ingress_upf_process_ingress_l4port_ingress_l4_dst_port_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4_dst_port, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_process_ingress_l4port_ingress_l4_dst_port_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_DST_PORT_ACT__NOP: 
                            {
                            }
                            break;
                        case INGRESS_UPF_PROCESS_INGRESS_L4PORT_INGRESS_L4_DST_PORT_ACT_INGRESS_UPF_PROCESS_INGRESS_L4PORT_SET_INGRESS_DST_PORT_RANGE_ID: 
                            {
meta->upf.dst_port_range_id = value->u.ingress_upf_process_ingress_l4port_set_ingress_dst_port_range_id.range_id;
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
            upf_ingress_hasReturned = false;
                        {
                /* construct key */
                struct ingress_upf_ingress_source_interface_lookup_by_port_key key = {};
                key.field0 = istd.ingress_port;
                /* value */
                struct ingress_upf_ingress_source_interface_lookup_by_port_value *value = NULL;
                /* perform lookup */
                value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_source_interface_lookup_by_port, &key);
                if (value == NULL) {
                    /* miss; find default action */
                    hit_3 = 0;
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_source_interface_lookup_by_port_defaultAction, &ebpf_zero);
                } else {
                    hit_3 = 1;
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_UPF_INGRESS_SOURCE_INTERFACE_LOOKUP_BY_PORT_ACT_INGRESS_UPF_INGRESS_SET_SOURCE_INTERFACE: 
                            {
meta->upf.src = value->u.ingress_upf_ingress_set_source_interface.src;
                            }
                            break;
                        case INGRESS_UPF_INGRESS_SOURCE_INTERFACE_LOOKUP_BY_PORT_ACT__NOP: 
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
            if (            hdr->gtpu.ebpf_valid) {
                {
                    /* construct key */
                    struct ingress_upf_ingress_session_lookup_by_teid_key key = {};
                    key.field0 = hdr->gtpu.teid;
                    /* value */
                    struct ingress_upf_ingress_session_lookup_by_teid_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_session_lookup_by_teid, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_session_lookup_by_teid_defaultAction, &ebpf_zero);
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_TEID_ACT_INGRESS_UPF_INGRESS_SET_SEID: 
                                {
meta->upf.seid = value->u.ingress_upf_ingress_set_seid.seid;
                                }
                                break;
                            case INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_TEID_ACT__NOP: 
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
{
                        hdr->gtpu_ipv4.ebpf_valid = false;
                                                hdr->gtpu_udp.ebpf_valid = false;
                                                hdr->gtpu.ebpf_valid = false;
                        meta->upf.outer_dst_addr = hdr->ipv4.dstAddr;
                    };                }

                else {
{
meta_0 = ostd;
                        meta_0.drop = true;
                        ostd = meta_0;
                    };                }
            }

            else {
                {
                    /* construct key */
                    struct ingress_upf_ingress_session_lookup_by_ue_ip_key key = {};
                    key.field0 = hdr->ipv4.dstAddr;
                    /* value */
                    struct ingress_upf_ingress_session_lookup_by_ue_ip_value *value = NULL;
                    /* perform lookup */
                    value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_session_lookup_by_ue_ip, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_session_lookup_by_ue_ip_defaultAction, &ebpf_zero);
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_UE_IP_ACT_INGRESS_UPF_INGRESS_SET_SEID: 
                                {
meta->upf.seid = value->u.ingress_upf_ingress_set_seid.seid;
                                }
                                break;
                            case INGRESS_UPF_INGRESS_SESSION_LOOKUP_BY_UE_IP_ACT__NOP: 
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
;                }

                else {
upf_ingress_hasReturned = true;                }
            }

            if (upf_ingress_hasReturned) {
;            }

            else {
                {
                    /* construct key */
                    struct ingress_upf_ingress_pdr_lookup_key key = {};
                    key.field0 = meta->upf.seid;
                    key.field1 = hdr->ipv4.srcAddr;
                    key.field2 = hdr->ipv4.dstAddr;
                    key.field3 = hdr->ipv4.protocol;
                    key.field4 = meta->upf.src_port_range_id;
                    key.field5 = meta->upf.dst_port_range_id;
                    key.field6 = meta->upf.src;
                    /* value */
                    struct ingress_upf_ingress_pdr_lookup_value *value = NULL;
                    /* perform lookup */
                    struct ingress_upf_ingress_pdr_lookup_value_cache* cached_value = NULL;
                    cached_value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_pdr_lookup_cache, &key);
                    if (cached_value != NULL) {
                        value = &(cached_value->value);
                        hit_3 = cached_value->hit;
                    } else {
                        struct ingress_upf_ingress_pdr_lookup_key_mask head = {0};
                        struct ingress_upf_ingress_pdr_lookup_value_mask *val = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_pdr_lookup_prefixes, &head);
                        if (val && val->has_next != 0) {
                            struct ingress_upf_ingress_pdr_lookup_key_mask next = val->next_tuple_mask;
                            #pragma clang loop unroll(disable)
                            for (int i = 0; i < MAX_INGRESS_UPF_INGRESS_PDR_LOOKUP_KEY_MASKS; i++) {
                                struct ingress_upf_ingress_pdr_lookup_value_mask *v = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_pdr_lookup_prefixes, &next);
                                if (!v) {
                                    break;
                                }
                                struct ingress_upf_ingress_pdr_lookup_key k = {};
                                __u32 *chunk = ((__u32 *) &k);
                                __u32 *mask = ((__u32 *) &next);
                                #pragma clang loop unroll(disable)
                                for (int i = 0; i < sizeof(struct ingress_upf_ingress_pdr_lookup_key_mask) / 4; i++) {
                                    chunk[i] = ((__u32 *) &key)[i] & mask[i];
                                }
                                __u32 tuple_id = v->tuple_id;
                                next = v->next_tuple_mask;
                                struct bpf_elf_map *tuple = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_pdr_lookup_tuples_map, &tuple_id);
                                if (!tuple) {
                                    break;
                                }
                                struct ingress_upf_ingress_pdr_lookup_value *tuple_entry = bpf_map_lookup_elem(tuple, &k);
                                if (!tuple_entry) {
                                    if (v->has_next == 0) {
                                        break;
                                    }
                                    continue;
                                }
                                if (value == NULL || tuple_entry->priority > value->priority) {
                                    value = tuple_entry;
                                }
                                if (v->has_next == 0) {
                                    break;
                                }
                            }
                        }
                        if (value == NULL) {
                            /* miss; find default action */
                            hit_3 = 0;
                            value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_pdr_lookup_defaultAction, &ebpf_zero);
                        } else {
                            hit_3 = 1;
                        }
                        if (value != NULL) {
                            struct ingress_upf_ingress_pdr_lookup_value_cache cache_update = {0};
                            cache_update.hit = hit_3;
                            __builtin_memcpy((void *) &(cache_update.value), (void *) value, sizeof(struct ingress_upf_ingress_pdr_lookup_value));
                            BPF_MAP_UPDATE_ELEM(ingress_upf_ingress_pdr_lookup_cache, &key, &cache_update, BPF_ANY);
                        }
                    }
                    if (value != NULL) {
                        /* run action */
                        switch (value->action) {
                            case INGRESS_UPF_INGRESS_PDR_LOOKUP_ACT_INGRESS_UPF_INGRESS_SET_FAR_ID: 
                                {
meta->upf.far_id = value->u.ingress_upf_ingress_set_far_id.far_id;
                                }
                                break;
                            case INGRESS_UPF_INGRESS_PDR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP: 
                                {
{
meta_2 = ostd;
                                        meta_2.drop = true;
                                        ostd = meta_2;
                                    }
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
                    {
                        /* construct key */
                        struct ingress_upf_ingress_far_lookup_key key = {};
                        key.field0 = meta->upf.far_id;
                        /* value */
                        struct ingress_upf_ingress_far_lookup_value *value = NULL;
                        /* perform lookup */
                        value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_far_lookup, &key);
                        if (value == NULL) {
                            /* miss; find default action */
                            hit_3 = 0;
                            value = BPF_MAP_LOOKUP_ELEM(ingress_upf_ingress_far_lookup_defaultAction, &ebpf_zero);
                        } else {
                            hit_3 = 1;
                        }
                        if (value != NULL) {
                            /* run action */
                            switch (value->action) {
                                case INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_FAR_FORWARD: 
                                    {
meta->upf.dest = value->u.ingress_upf_ingress_far_forward.dest;
                                    }
                                    break;
                                case INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_FAR_ENCAP_FORWARD: 
                                    {
meta->upf.dest = value->u.ingress_upf_ingress_far_encap_forward.dest;
                                        meta->upf.teid = value->u.ingress_upf_ingress_far_encap_forward.teid;
                                        meta->upf.gtpu_remote_ip = value->u.ingress_upf_ingress_far_encap_forward.gtpu_remote_ip;
                                        meta->upf.gtpu_local_ip = value->u.ingress_upf_ingress_far_encap_forward.gtpu_local_ip;
                                        meta->upf.outer_dst_addr = value->u.ingress_upf_ingress_far_encap_forward.gtpu_remote_ip;
                                    }
                                    break;
                                case INGRESS_UPF_INGRESS_FAR_LOOKUP_ACT_INGRESS_UPF_INGRESS_DROP: 
                                    {
{
meta_3 = ostd;
                                            meta_3.drop = true;
                                            ostd = meta_3;
                                        }
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
meta->upf.ipv4_len = hdr->ipv4.totalLen;                    }
                }

                if (meta->upf.dest == 0 || meta->upf.dest == 1) {
{
                        hdr->gtpu_ipv4.ebpf_valid = true;
                        hdr->gtpu_ipv4.version = 4;
                        hdr->gtpu_ipv4.ihl = 5;
                        hdr->gtpu_ipv4.dscp = 0;
                        hdr->gtpu_ipv4.ecn = 0;
                        hdr->gtpu_ipv4.totalLen = hdr->ipv4.totalLen + 36;
                        hdr->gtpu_ipv4.identification = 5395;
                        hdr->gtpu_ipv4.flags = 0;
                        hdr->gtpu_ipv4.fragOffset = 0;
                        hdr->gtpu_ipv4.ttl = 64;
                        hdr->gtpu_ipv4.protocol = 17;
                        hdr->gtpu_ipv4.dstAddr = meta->upf.gtpu_remote_ip;
                        hdr->gtpu_ipv4.srcAddr = meta->upf.gtpu_local_ip;
                        hdr->gtpu_ipv4.hdrChecksum = 0;
                                                hdr->gtpu_udp.ebpf_valid = true;
                        hdr->gtpu_udp.sport = 2152;
                        hdr->gtpu_udp.dport = 2152;
                        hdr->gtpu_udp.len = meta->upf.ipv4_len + 16;
                        hdr->gtpu_udp.checksum = 0;
                                                hdr->gtpu.ebpf_valid = true;
                        hdr->gtpu.version = 1;
                        hdr->gtpu.pt = 1;
                        hdr->gtpu.spare = 0;
                        hdr->gtpu.ex_flag = 0;
                        hdr->gtpu.seq_flag = 0;
                        hdr->gtpu.npdu_flag = 0;
                        hdr->gtpu.msgtype = 255;
                        hdr->gtpu.msglen = meta->upf.ipv4_len;
                        hdr->gtpu.teid = meta->upf.teid;
                    };                }

            }
                        {
                /* construct key */
                struct ingress_ip_forward_ipv4_lpm_key key = {};
                key.prefixlen = sizeof(key)*8 - 32;
                key.field0 = meta->upf.dest;
                u32 tmp_field1 = meta->upf.outer_dst_addr;
                key.field1 = bpf_htonl(tmp_field1);
                /* value */
                struct ingress_ip_forward_ipv4_lpm_value *value = NULL;
                /* perform lookup */
                struct ingress_ip_forward_ipv4_lpm_value_cache* cached_value = NULL;
                cached_value = BPF_MAP_LOOKUP_ELEM(ingress_ip_forward_ipv4_lpm_cache, &key);
                if (cached_value != NULL) {
                    value = &(cached_value->value);
                    hit_3 = cached_value->hit;
                } else {
                    value = BPF_MAP_LOOKUP_ELEM(ingress_ip_forward_ipv4_lpm, &key);
                    if (value == NULL) {
                        /* miss; find default action */
                        hit_3 = 0;
                        value = BPF_MAP_LOOKUP_ELEM(ingress_ip_forward_ipv4_lpm_defaultAction, &ebpf_zero);
                    } else {
                        hit_3 = 1;
                    }
                    if (value != NULL) {
                        struct ingress_ip_forward_ipv4_lpm_value_cache cache_update = {0};
                        cache_update.hit = hit_3;
                        __builtin_memcpy((void *) &(cache_update.value), (void *) value, sizeof(struct ingress_ip_forward_ipv4_lpm_value));
                        BPF_MAP_UPDATE_ELEM(ingress_ip_forward_ipv4_lpm_cache, &key, &cache_update, BPF_ANY);
                    }
                }
                if (value != NULL) {
                    /* run action */
                    switch (value->action) {
                        case INGRESS_IP_FORWARD_IPV4_LPM_ACT_INGRESS_IP_FORWARD_FORWARD: 
                            {
{
meta_7 = ostd;
                                    egress_port_1 = value->u.ingress_ip_forward_forward.port;
                                    meta_7.drop = false;
                                    meta_7.multicast_group = 0;
                                    meta_7.egress_port = egress_port_1;
                                    ostd = meta_7;
                                }
                                hdr->ethernet.srcAddr = value->u.ingress_ip_forward_forward.srcAddr;
                                hdr->ethernet.dstAddr = value->u.ingress_ip_forward_forward.dstAddr;
                                hdr->ipv4.ttl = hdr->ipv4.ttl + 255;
                            }
                            break;
                        case INGRESS_IP_FORWARD_IPV4_LPM_ACT_INGRESS_IP_FORWARD_DROP: 
                            {
{
meta_4 = ostd;
                                    meta_4.drop = true;
                                    ostd = meta_4;
                                }
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
        }
    }
    {
        return XDP_DROP;

        u16 ck_1_state = 0;
{
if (            hdr->gtpu_ipv4.ebpf_valid) {
                ck_1_state = 0;
;
                                {
                    u16 ck_1_tmp = 0;
                    ck_1_tmp = (hdr->gtpu_ipv4.version << 12) | (hdr->gtpu_ipv4.ihl << 8) | (hdr->gtpu_ipv4.dscp << 2) | hdr->gtpu_ipv4.ecn;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = hdr->gtpu_ipv4.totalLen;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = hdr->gtpu_ipv4.identification;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = (hdr->gtpu_ipv4.flags << 13) | hdr->gtpu_ipv4.fragOffset;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = (hdr->gtpu_ipv4.ttl << 8) | hdr->gtpu_ipv4.protocol;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = (hdr->gtpu_ipv4.srcAddr >> 16);
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = hdr->gtpu_ipv4.srcAddr;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = (hdr->gtpu_ipv4.dstAddr >> 16);
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                    ck_1_tmp = hdr->gtpu_ipv4.dstAddr;
                    ck_1_state = csum16_add(ck_1_state, ck_1_tmp);
                }
;
                hdr->gtpu_ipv4.hdrChecksum = ((u16) (~ck_1_state));
            }
                        ck_1_state = 0;
;
                        {
                u16 ck_1_tmp_0 = 0;
                ck_1_tmp_0 = hdr->ipv4.hdrChecksum;
                ck_1_state = csum16_sub(ck_1_state, ck_1_tmp_0);
            }
;
                        {
                u16 ck_1_tmp_1 = 0;
                ck_1_tmp_1 = (hdr->ipv4.ttl << 8) | hdr->ipv4.protocol;
                ck_1_state = csum16_add(ck_1_state, ck_1_tmp_1);
            }
;
            hdr->ipv4.hdrChecksum = ((u16) (~ck_1_state));
            ;
            ;
            ;
            ;
            ;
            ;
            ;
            ;
        }

        if (ostd.clone || ostd.multicast_group != 0) {
            struct xdp2tc_metadata xdp2tc_md = {};
            xdp2tc_md.headers = *hdr;
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
        if (hdr->ethernet.ebpf_valid) {
            outHeaderLength += 112;
        }
        if (hdr->gtpu_ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (hdr->gtpu_udp.ebpf_valid) {
            outHeaderLength += 64;
        }
        if (hdr->gtpu.ebpf_valid) {
            outHeaderLength += 64;
        }
        if (hdr->ipv4.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (hdr->udp.ebpf_valid) {
            outHeaderLength += 64;
        }
        if (hdr->tcp.ebpf_valid) {
            outHeaderLength += 160;
        }
        if (hdr->icmp.ebpf_valid) {
            outHeaderLength += 128;
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
        if (hdr->ethernet.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
                return XDP_ABORTED;
            }
            
            hdr->ethernet.dstAddr = htonll(hdr->ethernet.dstAddr << 16);
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            hdr->ethernet.srcAddr = htonll(hdr->ethernet.srcAddr << 16);
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_packetOffsetInBits += 48;

            hdr->ethernet.etherType = bpf_htons(hdr->ethernet.etherType);
            ebpf_byte = ((char*)(&hdr->ethernet.etherType))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ethernet.etherType))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (hdr->gtpu_ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ihl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dscp))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 2, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 6;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ecn))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 2, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 2;

            hdr->gtpu_ipv4.totalLen = bpf_htons(hdr->gtpu_ipv4.totalLen);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.totalLen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.totalLen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu_ipv4.identification = bpf_htons(hdr->gtpu_ipv4.identification);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.flags))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            hdr->gtpu_ipv4.fragOffset = bpf_htons(hdr->gtpu_ipv4.fragOffset << 3);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.fragOffset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.fragOffset))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
            ebpf_packetOffsetInBits += 13;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->gtpu_ipv4.hdrChecksum = bpf_htons(hdr->gtpu_ipv4.hdrChecksum);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.hdrChecksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.hdrChecksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu_ipv4.srcAddr = htonl(hdr->gtpu_ipv4.srcAddr);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            hdr->gtpu_ipv4.dstAddr = htonl(hdr->gtpu_ipv4.dstAddr);
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
        if (hdr->gtpu_udp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
                return XDP_ABORTED;
            }
            
            hdr->gtpu_udp.sport = bpf_htons(hdr->gtpu_udp.sport);
            ebpf_byte = ((char*)(&hdr->gtpu_udp.sport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_udp.sport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu_udp.dport = bpf_htons(hdr->gtpu_udp.dport);
            ebpf_byte = ((char*)(&hdr->gtpu_udp.dport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_udp.dport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu_udp.len = bpf_htons(hdr->gtpu_udp.len);
            ebpf_byte = ((char*)(&hdr->gtpu_udp.len))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_udp.len))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu_udp.checksum = bpf_htons(hdr->gtpu_udp.checksum);
            ebpf_byte = ((char*)(&hdr->gtpu_udp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu_udp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (hdr->gtpu.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&hdr->gtpu.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&hdr->gtpu.pt))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&hdr->gtpu.spare))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 3, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&hdr->gtpu.ex_flag))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 2, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&hdr->gtpu.seq_flag))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 1, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&hdr->gtpu.npdu_flag))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 1;

            ebpf_byte = ((char*)(&hdr->gtpu.msgtype))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->gtpu.msglen = bpf_htons(hdr->gtpu.msglen);
            ebpf_byte = ((char*)(&hdr->gtpu.msglen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu.msglen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->gtpu.teid = htonl(hdr->gtpu.teid);
            ebpf_byte = ((char*)(&hdr->gtpu.teid))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu.teid))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu.teid))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->gtpu.teid))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
        if (hdr->ipv4.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&hdr->ipv4.version))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->ipv4.ihl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->ipv4.dscp))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 2, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 6;

            ebpf_byte = ((char*)(&hdr->ipv4.ecn))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 2, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 2;

            hdr->ipv4.totalLen = bpf_htons(hdr->ipv4.totalLen);
            ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->ipv4.identification = bpf_htons(hdr->ipv4.identification);
            ebpf_byte = ((char*)(&hdr->ipv4.identification))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.identification))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            ebpf_byte = ((char*)(&hdr->ipv4.flags))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            hdr->ipv4.fragOffset = bpf_htons(hdr->ipv4.fragOffset << 3);
            ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[1];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
            ebpf_packetOffsetInBits += 13;

            ebpf_byte = ((char*)(&hdr->ipv4.ttl))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->ipv4.protocol))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->ipv4.hdrChecksum = bpf_htons(hdr->ipv4.hdrChecksum);
            ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->ipv4.srcAddr = htonl(hdr->ipv4.srcAddr);
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            hdr->ipv4.dstAddr = htonl(hdr->ipv4.dstAddr);
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

        }
        if (hdr->udp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
                return XDP_ABORTED;
            }
            
            hdr->udp.sport = bpf_htons(hdr->udp.sport);
            ebpf_byte = ((char*)(&hdr->udp.sport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.sport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->udp.dport = bpf_htons(hdr->udp.dport);
            ebpf_byte = ((char*)(&hdr->udp.dport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.dport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->udp.len = bpf_htons(hdr->udp.len);
            ebpf_byte = ((char*)(&hdr->udp.len))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.len))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->udp.checksum = bpf_htons(hdr->udp.checksum);
            ebpf_byte = ((char*)(&hdr->udp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->udp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (hdr->tcp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
                return XDP_ABORTED;
            }
            
            hdr->tcp.sport = bpf_htons(hdr->tcp.sport);
            ebpf_byte = ((char*)(&hdr->tcp.sport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.sport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.dport = bpf_htons(hdr->tcp.dport);
            ebpf_byte = ((char*)(&hdr->tcp.dport))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.dport))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.seq_no = htonl(hdr->tcp.seq_no);
            ebpf_byte = ((char*)(&hdr->tcp.seq_no))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.seq_no))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.seq_no))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.seq_no))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            hdr->tcp.ack_no = htonl(hdr->tcp.ack_no);
            ebpf_byte = ((char*)(&hdr->tcp.ack_no))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.ack_no))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.ack_no))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.ack_no))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_packetOffsetInBits += 32;

            ebpf_byte = ((char*)(&hdr->tcp.data_offset))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 4;

            ebpf_byte = ((char*)(&hdr->tcp.res))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 1, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&hdr->tcp.ecn))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 7));
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 7, 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 3;

            ebpf_byte = ((char*)(&hdr->tcp.ctrl))[0];
            write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 0, (ebpf_byte >> 0));
            ebpf_packetOffsetInBits += 6;

            hdr->tcp.window = bpf_htons(hdr->tcp.window);
            ebpf_byte = ((char*)(&hdr->tcp.window))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.window))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.checksum = bpf_htons(hdr->tcp.checksum);
            ebpf_byte = ((char*)(&hdr->tcp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->tcp.urgent_ptr = bpf_htons(hdr->tcp.urgent_ptr);
            ebpf_byte = ((char*)(&hdr->tcp.urgent_ptr))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->tcp.urgent_ptr))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

        }
        if (hdr->icmp.ebpf_valid) {
            if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 128)) {
                return XDP_ABORTED;
            }
            
            ebpf_byte = ((char*)(&hdr->icmp.icmp_type))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            ebpf_byte = ((char*)(&hdr->icmp.icmp_code))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_packetOffsetInBits += 8;

            hdr->icmp.checksum = bpf_htons(hdr->icmp.checksum);
            ebpf_byte = ((char*)(&hdr->icmp.checksum))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.checksum))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->icmp.identifier = bpf_htons(hdr->icmp.identifier);
            ebpf_byte = ((char*)(&hdr->icmp.identifier))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.identifier))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->icmp.sequence_number = bpf_htons(hdr->icmp.sequence_number);
            ebpf_byte = ((char*)(&hdr->icmp.sequence_number))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.sequence_number))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_packetOffsetInBits += 16;

            hdr->icmp.timestamp = htonll(hdr->icmp.timestamp);
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[0];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[1];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[2];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[3];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[4];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[5];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[6];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 6, (ebpf_byte));
            ebpf_byte = ((char*)(&hdr->icmp.timestamp))[7];
            write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 7, (ebpf_byte));
            ebpf_packetOffsetInBits += 64;

        }

    }
    return bpf_redirect_map(&tx_port, ostd.egress_port%DEVMAP_SIZE, 0);
}

SEC("xdp_devmap/xdp-egress")
int xdp_egress_func(struct xdp_md *skb) {
    struct metadata *user_meta;

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
    struct headers *parsed_hdr;
    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_one);
    if (!hdrMd)
        return XDP_DROP;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    parsed_hdr = &(hdrMd->cpumap_hdr);
    user_meta = &(hdrMd->cpumap_usermeta);
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
        {
        }
    }
    {
{
        }

        if (ostd.drop) {
            return XDP_ABORTED;
        }
        int outHeaderLength = 0;

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
        struct headers *hdr;
    hdr = &(xdp2tc_md.headers);
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
    if (hdr->ethernet.ebpf_valid) {
        outHeaderLength += 112;
    }
    if (hdr->gtpu_ipv4.ebpf_valid) {
        outHeaderLength += 160;
    }
    if (hdr->gtpu_udp.ebpf_valid) {
        outHeaderLength += 64;
    }
    if (hdr->gtpu.ebpf_valid) {
        outHeaderLength += 64;
    }
    if (hdr->ipv4.ebpf_valid) {
        outHeaderLength += 160;
    }
    if (hdr->udp.ebpf_valid) {
        outHeaderLength += 64;
    }
    if (hdr->tcp.ebpf_valid) {
        outHeaderLength += 160;
    }
    if (hdr->icmp.ebpf_valid) {
        outHeaderLength += 128;
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
    if (hdr->ethernet.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 112)) {
            return XDP_ABORTED;
        }
        
        hdr->ethernet.dstAddr = htonll(hdr->ethernet.dstAddr << 16);
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[4];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.dstAddr))[5];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
        ebpf_packetOffsetInBits += 48;

        hdr->ethernet.srcAddr = htonll(hdr->ethernet.srcAddr << 16);
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[4];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.srcAddr))[5];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
        ebpf_packetOffsetInBits += 48;

        hdr->ethernet.etherType = bpf_htons(hdr->ethernet.etherType);
        ebpf_byte = ((char*)(&hdr->ethernet.etherType))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ethernet.etherType))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (hdr->gtpu_ipv4.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.version))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ihl))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dscp))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 2, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 6;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ecn))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 2, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 2;

        hdr->gtpu_ipv4.totalLen = bpf_htons(hdr->gtpu_ipv4.totalLen);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.totalLen))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.totalLen))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu_ipv4.identification = bpf_htons(hdr->gtpu_ipv4.identification);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.identification))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.identification))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.flags))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        hdr->gtpu_ipv4.fragOffset = bpf_htons(hdr->gtpu_ipv4.fragOffset << 3);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.fragOffset))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.fragOffset))[1];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
        ebpf_packetOffsetInBits += 13;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.ttl))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.protocol))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        hdr->gtpu_ipv4.hdrChecksum = bpf_htons(hdr->gtpu_ipv4.hdrChecksum);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.hdrChecksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.hdrChecksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu_ipv4.srcAddr = htonl(hdr->gtpu_ipv4.srcAddr);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.srcAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        hdr->gtpu_ipv4.dstAddr = htonl(hdr->gtpu_ipv4.dstAddr);
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_ipv4.dstAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

    }
    if (hdr->gtpu_udp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
            return XDP_ABORTED;
        }
        
        hdr->gtpu_udp.sport = bpf_htons(hdr->gtpu_udp.sport);
        ebpf_byte = ((char*)(&hdr->gtpu_udp.sport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_udp.sport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu_udp.dport = bpf_htons(hdr->gtpu_udp.dport);
        ebpf_byte = ((char*)(&hdr->gtpu_udp.dport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_udp.dport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu_udp.len = bpf_htons(hdr->gtpu_udp.len);
        ebpf_byte = ((char*)(&hdr->gtpu_udp.len))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_udp.len))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu_udp.checksum = bpf_htons(hdr->gtpu_udp.checksum);
        ebpf_byte = ((char*)(&hdr->gtpu_udp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu_udp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (hdr->gtpu.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&hdr->gtpu.version))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&hdr->gtpu.pt))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        ebpf_byte = ((char*)(&hdr->gtpu.spare))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 3, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        ebpf_byte = ((char*)(&hdr->gtpu.ex_flag))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 2, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        ebpf_byte = ((char*)(&hdr->gtpu.seq_flag))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 1, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        ebpf_byte = ((char*)(&hdr->gtpu.npdu_flag))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 1;

        ebpf_byte = ((char*)(&hdr->gtpu.msgtype))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        hdr->gtpu.msglen = bpf_htons(hdr->gtpu.msglen);
        ebpf_byte = ((char*)(&hdr->gtpu.msglen))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu.msglen))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->gtpu.teid = htonl(hdr->gtpu.teid);
        ebpf_byte = ((char*)(&hdr->gtpu.teid))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu.teid))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu.teid))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->gtpu.teid))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

    }
    if (hdr->ipv4.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&hdr->ipv4.version))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&hdr->ipv4.ihl))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&hdr->ipv4.dscp))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 2, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 6;

        ebpf_byte = ((char*)(&hdr->ipv4.ecn))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 2, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 2;

        hdr->ipv4.totalLen = bpf_htons(hdr->ipv4.totalLen);
        ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.totalLen))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->ipv4.identification = bpf_htons(hdr->ipv4.identification);
        ebpf_byte = ((char*)(&hdr->ipv4.identification))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.identification))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        ebpf_byte = ((char*)(&hdr->ipv4.flags))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 5, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        hdr->ipv4.fragOffset = bpf_htons(hdr->ipv4.fragOffset << 3);
        ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 5, 0, (ebpf_byte >> 3));
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 3, 5, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.fragOffset))[1];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 1, 5, 0, (ebpf_byte >> 3));
        ebpf_packetOffsetInBits += 13;

        ebpf_byte = ((char*)(&hdr->ipv4.ttl))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        ebpf_byte = ((char*)(&hdr->ipv4.protocol))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        hdr->ipv4.hdrChecksum = bpf_htons(hdr->ipv4.hdrChecksum);
        ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.hdrChecksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->ipv4.srcAddr = htonl(hdr->ipv4.srcAddr);
        ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.srcAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        hdr->ipv4.dstAddr = htonl(hdr->ipv4.dstAddr);
        ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->ipv4.dstAddr))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

    }
    if (hdr->udp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 64)) {
            return XDP_ABORTED;
        }
        
        hdr->udp.sport = bpf_htons(hdr->udp.sport);
        ebpf_byte = ((char*)(&hdr->udp.sport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->udp.sport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.dport = bpf_htons(hdr->udp.dport);
        ebpf_byte = ((char*)(&hdr->udp.dport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->udp.dport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.len = bpf_htons(hdr->udp.len);
        ebpf_byte = ((char*)(&hdr->udp.len))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->udp.len))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->udp.checksum = bpf_htons(hdr->udp.checksum);
        ebpf_byte = ((char*)(&hdr->udp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->udp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (hdr->tcp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 160)) {
            return XDP_ABORTED;
        }
        
        hdr->tcp.sport = bpf_htons(hdr->tcp.sport);
        ebpf_byte = ((char*)(&hdr->tcp.sport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.sport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.dport = bpf_htons(hdr->tcp.dport);
        ebpf_byte = ((char*)(&hdr->tcp.dport))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.dport))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.seq_no = htonl(hdr->tcp.seq_no);
        ebpf_byte = ((char*)(&hdr->tcp.seq_no))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.seq_no))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.seq_no))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.seq_no))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        hdr->tcp.ack_no = htonl(hdr->tcp.ack_no);
        ebpf_byte = ((char*)(&hdr->tcp.ack_no))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.ack_no))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.ack_no))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.ack_no))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_packetOffsetInBits += 32;

        ebpf_byte = ((char*)(&hdr->tcp.data_offset))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 4, 4, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 4;

        ebpf_byte = ((char*)(&hdr->tcp.res))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 3, 1, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&hdr->tcp.ecn))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 1, 0, (ebpf_byte >> 7));
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0 + 1, 7, 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 3;

        ebpf_byte = ((char*)(&hdr->tcp.ctrl))[0];
        write_partial(pkt + BYTES(ebpf_packetOffsetInBits) + 0, 6, 0, (ebpf_byte >> 0));
        ebpf_packetOffsetInBits += 6;

        hdr->tcp.window = bpf_htons(hdr->tcp.window);
        ebpf_byte = ((char*)(&hdr->tcp.window))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.window))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.checksum = bpf_htons(hdr->tcp.checksum);
        ebpf_byte = ((char*)(&hdr->tcp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->tcp.urgent_ptr = bpf_htons(hdr->tcp.urgent_ptr);
        ebpf_byte = ((char*)(&hdr->tcp.urgent_ptr))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->tcp.urgent_ptr))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

    }
    if (hdr->icmp.ebpf_valid) {
        if (ebpf_packetEnd < pkt + BYTES(ebpf_packetOffsetInBits + 128)) {
            return XDP_ABORTED;
        }
        
        ebpf_byte = ((char*)(&hdr->icmp.icmp_type))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        ebpf_byte = ((char*)(&hdr->icmp.icmp_code))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_packetOffsetInBits += 8;

        hdr->icmp.checksum = bpf_htons(hdr->icmp.checksum);
        ebpf_byte = ((char*)(&hdr->icmp.checksum))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.checksum))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->icmp.identifier = bpf_htons(hdr->icmp.identifier);
        ebpf_byte = ((char*)(&hdr->icmp.identifier))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.identifier))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->icmp.sequence_number = bpf_htons(hdr->icmp.sequence_number);
        ebpf_byte = ((char*)(&hdr->icmp.sequence_number))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.sequence_number))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_packetOffsetInBits += 16;

        hdr->icmp.timestamp = htonll(hdr->icmp.timestamp);
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[0];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 0, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[1];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 1, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[2];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 2, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[3];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 3, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[4];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 4, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[5];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 5, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[6];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 6, (ebpf_byte));
        ebpf_byte = ((char*)(&hdr->icmp.timestamp))[7];
        write_byte(pkt, BYTES(ebpf_packetOffsetInBits) + 7, (ebpf_byte));
        ebpf_packetOffsetInBits += 64;

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
    struct metadata *user_meta;
    struct hdr_md *hdrMd;
    struct headers *parsed_hdr;    hdrMd = BPF_MAP_LOOKUP_ELEM(hdr_md_cpumap, &ebpf_one);
    if (!hdrMd)
        return TC_ACT_SHOT;
    __builtin_memset(hdrMd, 0, sizeof(struct hdr_md));

    parsed_hdr = &(hdrMd->cpumap_hdr);
    user_meta = &(hdrMd->cpumap_usermeta);
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
        {
        }
    }
    {
{
        }

        int outHeaderLength = 0;

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
