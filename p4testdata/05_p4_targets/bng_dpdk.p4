#include <core.p4>
#include <psa.p4>

#define IP_VERSION_4 4
#define IP_VER_LENGTH 4
#define FWD_CLASSIFIER_TABLE_SIZE 1024
#define BRIDGING_TABLE_SIZE 1024
#define BNG_MAX_SUBSC 8192
#define BNG_MAX_NET_PER_SUBSC 4
#define BNG_MAX_SUBSC_NET BNG_MAX_NET_PER_SUBSC * BNG_MAX_SUBSC

typedef bit<8>  fwd_type_t;
typedef bit<32> next_id_t;
typedef bit<20> mpls_label_t;
typedef bit<48> mac_addr_t;
typedef bit<16> vlan_id_t;
typedef bit<32> ipv4_addr_t;

// PORT types. Set by the control plane using the actions
// of the filtering.ingress_port_vlan table.
typedef bit<8> port_type_t;
// Default value. Set by deny action.
const port_type_t PORT_TYPE_UNKNOWN = 0x0;
// Host-facing port on a leaf switch.
const port_type_t PORT_TYPE_EDGE = 0x1;
// Switch-facing port on a leaf or spine switch.
const port_type_t PORT_TYPE_INFRA = 0x2;

const fwd_type_t FWD_BRIDGING = 0;
const fwd_type_t FWD_MPLS = 1;
const fwd_type_t FWD_IPV4_UNICAST = 2;
const fwd_type_t FWD_IPV4_MULTICAST = 3;
const fwd_type_t FWD_IPV6_UNICAST = 4;
const fwd_type_t FWD_IPV6_MULTICAST = 5;
const fwd_type_t FWD_UNKNOWN = 7;

const bit<16> ETHERTYPE_QINQ = 0x88A8;
const bit<16> ETHERTYPE_QINQ_NON_STD = 0x9100;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_MPLS = 0x8847;
const bit<16> ETHERTYPE_MPLS_MULTICAST = 0x8848;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_PPPOED = 0x8863;
const bit<16> ETHERTYPE_PPPOES = 0x8864;

const bit<16> PPPOE_PROTOCOL_IP4 = 0x0021;
const bit<16> PPPOE_PROTOCOL_IP6 = 0x0057;

const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMPV6 = 58;

const vlan_id_t DEFAULT_VLAN_ID = 16w4094;

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> eth_type;
}

header vlan_tag_t {
    vlan_id_t vlan_id;
    bit<16> eth_type;
}

header mpls_t {
    bit<24> label;
    bit<8> ttl;
}

header pppoe_t {
    bit<8>  version_type;
    bit<8>  code;
    bit<16> session_id;
    bit<16> length;
    bit<16> protocol;
}

header ipv4_t {
    bit<8> version_ihl;
    bit<8> dscp;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header bridged_metadata_t {
    bit<32>   line_id;
    bit<16>   pppoe_session_id;
    vlan_id_t vlan_id;
    bit<8>    bng_type;
    bit<8>    fwd_type;
    bit<8>    push_double_vlan;
    vlan_id_t   inner_vlan_id;
}

typedef bit<8> bng_type_t;
const bng_type_t BNG_TYPE_INVALID = 8w0x0;
const bng_type_t BNG_TYPE_UPSTREAM = 8w0x1;
const bng_type_t BNG_TYPE_DOWNSTREAM = 8w0x2;

struct empty_metadata_t { };

struct bng_meta_t {
    bng_type_t    type; // upstream or downstream
    bit<32>   line_id; // subscriber line
    bit<16>   pppoe_session_id;
    PSA_MeterColor_t   ds_meter_result; // for downstream metering
    vlan_id_t s_tag;
    vlan_id_t c_tag;
}

struct local_metadata_t {
    bit<16>       eth_type;
    bit<16>       ip_eth_type;
    vlan_id_t     vlan_id;
    bool         push_double_vlan;
    vlan_id_t     inner_vlan_id;
    bool         skip_forwarding;
    fwd_type_t    fwd_type;
    bit<24>       mpls_label;
    bit<8>        mpls_ttl;
    bit<8>        ip_proto;
    bit<16>       l4_sport;
    bit<16>       l4_dport;
    bit<32>       ipv4_src_addr;
    bit<32>       ipv4_dst_addr;
    bng_meta_t    bng;
    port_type_t   port_type;
}

struct headers_t {
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
    vlan_tag_t inner_vlan_tag;
    pppoe_t pppoe;
    ipv4_t ipv4;
}


parser packet_parser(packet_in packet, out headers_t hdr, inout local_metadata_t local_metadata, in psa_ingress_parser_input_metadata_t standard_metadata, in empty_metadata_t resub_meta, in empty_metadata_t recirc_meta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        local_metadata.eth_type = hdr.ethernet.eth_type;
        local_metadata.vlan_id = DEFAULT_VLAN_ID;
        transition select(hdr.ethernet.eth_type) {
            ETHERTYPE_VLAN: parse_qinq;
            ETHERTYPE_QINQ: parse_qinq;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_qinq {
        packet.extract(hdr.vlan_tag);
        local_metadata.eth_type = hdr.vlan_tag.eth_type;
        transition select(hdr.vlan_tag.eth_type) {
            16w0x8100: parse_inner_vlan_tag;
            default: accept;
        }
    }

    state parse_inner_vlan_tag {
        packet.extract(hdr.inner_vlan_tag);
        local_metadata.eth_type =  hdr.inner_vlan_tag.eth_type;
        local_metadata.inner_vlan_id = hdr.inner_vlan_tag.vlan_id;
        local_metadata.bng.c_tag = hdr.inner_vlan_tag.vlan_id;
        transition select(hdr.inner_vlan_tag.eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_PPPOED: parse_pppoe;
            ETHERTYPE_PPPOES: parse_pppoe;
            default: accept;
        }
    }

    state parse_pppoe {
        packet.extract(hdr.pppoe);
        transition select(hdr.pppoe.protocol) {
            PPPOE_PROTOCOL_IP4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        local_metadata.ip_eth_type = ETHERTYPE_IPV4;
        local_metadata.ipv4_dst_addr = hdr.ipv4.dst_addr;
        transition accept;
    }
}

control packet_deparser(packet_out packet, out empty_metadata_t clone_i2e_meta, out empty_metadata_t resubmit_meta,
                        out empty_metadata_t normal_meta, inout headers_t hdr, in local_metadata_t local_metadata,
                        in psa_ingress_output_metadata_t istd) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag);
        packet.emit(hdr.inner_vlan_tag);
        packet.emit(hdr.pppoe);
        packet.emit(hdr.ipv4);
    }

}

control ingress(inout headers_t hdr, inout local_metadata_t local_metadata, in psa_ingress_input_metadata_t standard_metadata,
                inout psa_ingress_output_metadata_t ostd) {

    Counter<bit<32>, bit<32>>(BNG_MAX_SUBSC, PSA_CounterType_t.PACKETS) c_line_rx;
    Counter<bit<32>, bit<32>>(BNG_MAX_SUBSC, PSA_CounterType_t.PACKETS) c_terminated;
    Counter<bit<32>, bit<32>>(BNG_MAX_SUBSC, PSA_CounterType_t.PACKETS) c_dropped;
    Counter<bit<32>, bit<32>>(BNG_MAX_SUBSC, PSA_CounterType_t.PACKETS) c_control;
    Counter<bit<32>, bit<32>>(BNG_MAX_SUBSC, PSA_CounterType_t.PACKETS) c_line_tx;

    Meter<bit<32>>(BNG_MAX_SUBSC, PSA_MeterType_t.BYTES) m_besteff;
    Meter<bit<32>>(BNG_MAX_SUBSC, PSA_MeterType_t.BYTES) m_prio;

    action deny() {
        // Packet from unconfigured port. Skip forwarding and next block.
        local_metadata.skip_forwarding = true;
        local_metadata.port_type = PORT_TYPE_UNKNOWN;
    }

    action permit_default() {
        local_metadata.port_type = 0x1;
    }

    action permit(port_type_t port_type) {
        // Allow packet as is.
        local_metadata.port_type = port_type;
    }

    action permit_with_internal_vlan(vlan_id_t vlan_id, port_type_t port_type) {
        local_metadata.vlan_id = vlan_id;
        permit(port_type);
    }

    table ingress_port_vlan {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.vlan_tag.vlan_id           : ternary @name("vlan_id");
            hdr.inner_vlan_tag.vlan_id     : ternary @name("inner_vlan_id");
        }
        actions = {
            deny();
            permit();
            permit_with_internal_vlan();
        }
        const default_action = deny();
        size = BNG_MAX_SUBSC;
    }

    action set_forwarding_type(fwd_type_t fwd_type) {
        local_metadata.fwd_type = fwd_type;
        local_metadata.skip_forwarding = false;
    }

    // DPDK does not support non-zero default actions
    // So, let's add extra action w/o any argument
    action set_forwarding_type_default() {
        local_metadata.fwd_type = FWD_IPV4_UNICAST;
        local_metadata.skip_forwarding = false;
    }

    /*
     * Forwarding Classifier.
     *
     * Set which type of forwarding behavior to execute in the next control block.
     * There are six types of tables in Forwarding control block:
     * - Bridging: default forwarding type
     * - MPLS: destination mac address is the router mac and ethernet type is
     *   MPLS(0x8847)
     * - IP Multicast: destination mac address is multicast address and ethernet
     *   type is IP(0x0800 or 0x86dd)
     * - IP Unicast: destination mac address is router mac and ethernet type is
     *   IP(0x0800 or 0x86dd)
     */
    table fwd_classifier {
        key = {
            hdr.ethernet.dst_addr          : ternary @name("eth_dst");
            standard_metadata.ingress_port : exact @name("ig_port");
            local_metadata.eth_type        : ternary @name("eth_type");
            local_metadata.ip_eth_type     : exact @name("ip_eth_type");
        }
        actions = {
            set_forwarding_type;
            set_forwarding_type_default;
        }
        const default_action = set_forwarding_type_default();
        size = FWD_CLASSIFIER_TABLE_SIZE;
    }

    action route(PortId_t port_num, mac_addr_t smac, mac_addr_t dmac) {
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        send_to_port(ostd, port_num);
    }

    table routing_v4 {
        key = {
            hdr.ipv4.dst_addr: lpm @name("ipv4_dst");
        }
        actions = {
            route;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    action set_vlan(vlan_id_t vlan_id) {
        local_metadata.vlan_id = vlan_id;
    }

    action set_double_vlan(vlan_id_t outer_vlan_id, vlan_id_t inner_vlan_id) {
        set_vlan(outer_vlan_id);
        local_metadata.push_double_vlan = true;
        local_metadata.inner_vlan_id = inner_vlan_id;
        local_metadata.bng.s_tag = outer_vlan_id;
        local_metadata.bng.c_tag = inner_vlan_id;
    }

    table next_vlan {
        key = {
            ostd.egress_port: exact @name("egress_port");
        }
        actions = {
            set_vlan;
            set_double_vlan;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 1024;
    }

    action set_line(bit<32> line_id) {
        local_metadata.bng.line_id = line_id;
    }

    // DPDK does not support non-zero default actions
    // So, let's add extra action w/o any argument
    action set_line_default() {
        local_metadata.bng.line_id = (bit<32>)0;
    }

    table t_line_map {
        key = {
            hdr.vlan_tag.vlan_id : exact @name("s_tag");
            hdr.inner_vlan_tag.vlan_id : exact @name("c_tag");
        }
         actions = {
            set_line;
            set_line_default;
        }
        size = BNG_MAX_SUBSC;
        // By default set the line ID to 0
        const default_action = set_line_default();
    }

    action punt_to_cpu() {
        //send_to_port(ostd, CPU_PORT);
        // Clean the multicast group, otherwise multicast decision
        //  will override the punting to CPU action
        ostd.multicast_group = (MulticastGroup_t) 0;
        c_control.count(local_metadata.bng.line_id);
    }

    table t_pppoe_cp {
        key = {
            hdr.pppoe.code     : exact   @name("pppoe_code");
        }
        actions = {
            punt_to_cpu;
            @defaultonly NoAction;
        }
        size = 16;
        const default_action = NoAction;
    }

    @hidden
    action term_enabled(bit<16> eth_type) {
        hdr.ethernet.eth_type = eth_type;
        hdr.pppoe.setInvalid();
        c_terminated.count(local_metadata.bng.line_id);
    }

    action term_disabled() {
        c_dropped.count(local_metadata.bng.line_id); 
        local_metadata.bng.type = BNG_TYPE_INVALID;
        ingress_drop(ostd);
    }

    action term_enabled_v4() {
        term_enabled(ETHERTYPE_IPV4);
    }

    table t_pppoe_term_v4 {
        key = {
            local_metadata.bng.line_id      : exact @name("line_id");
            hdr.ipv4.src_addr               : exact @name("ipv4_src");
            hdr.pppoe.session_id            : exact @name("pppoe_session_id");
        }
        actions = {
            term_enabled_v4;
            @defaultonly term_disabled;
        }
        size = BNG_MAX_SUBSC_NET;
        const default_action = term_disabled;
    }

    action set_session(bit<16> pppoe_session_id) {
        local_metadata.bng.type = BNG_TYPE_DOWNSTREAM;
        local_metadata.bng.pppoe_session_id = pppoe_session_id;
        c_line_rx.count(local_metadata.bng.line_id);
    }

    action drop() {
        local_metadata.bng.type = BNG_TYPE_DOWNSTREAM;
        c_line_rx.count(local_metadata.bng.line_id);
        ingress_drop(ostd);
    }

    table t_line_session_map {
        key = {
            local_metadata.bng.line_id : exact @name("line_id");
        }
        actions = {
            @defaultonly NoAction;
            set_session;
            drop;
        }
        size = BNG_MAX_SUBSC;
        const default_action = NoAction;
    }

    action qos_prio() {
        local_metadata.bng.ds_meter_result = m_prio.execute(index = local_metadata.bng.line_id, pkt_len = (bit<32>)hdr.ipv4.total_len);
        ostd.class_of_service = (ClassOfService_t) 1;
    }

    action qos_besteff() {
        local_metadata.bng.ds_meter_result = m_besteff.execute(index = local_metadata.bng.line_id, pkt_len = (bit<32>)hdr.ipv4.total_len);
        ostd.class_of_service = (ClassOfService_t) 0;
    }

    table t_qos_v4 {
        key = {
            local_metadata.bng.line_id : ternary @name("line_id");
            hdr.ipv4.src_addr : ternary     @name("ipv4_src");
            hdr.ipv4.dscp     : ternary @name("ipv4_dscp");
        }
        actions = {
            qos_prio;
            qos_besteff;
        }
        size = 256;
        const default_action = qos_besteff;
    }

    action push_outer_vlan() {
        // If VLAN is already valid, we overwrite it with a potentially new VLAN
        // ID, and same CFI, PRI, and eth_type values found in ingress.
        hdr.vlan_tag.setValid();
        hdr.vlan_tag.eth_type = ETHERTYPE_QINQ;
        hdr.vlan_tag.vlan_id = local_metadata.vlan_id;
    }

    action push_inner_vlan() {
        // Push inner VLAN TAG, rewriting correclty the outer vlan eth_type
        hdr.inner_vlan_tag.setValid();
        hdr.inner_vlan_tag.vlan_id = local_metadata.inner_vlan_id;
        hdr.inner_vlan_tag.eth_type = ETHERTYPE_VLAN;
        hdr.vlan_tag.eth_type = ETHERTYPE_VLAN;
    }

    action push_vlan() {
        push_outer_vlan();
    }

    action pop_vlan() {
        hdr.vlan_tag.setInvalid();
    }

    action eg_drop() {
        ingress_drop(ostd);
    }

    table egress_vlan {
        key = {
            ostd.egress_port: exact @name("eg_port");
        }
        actions = {
            push_vlan;
            pop_vlan;
            @defaultonly eg_drop;
        }
        const default_action = eg_drop();
        size = 1024;
    }

    @hidden
    action encap() {
        // Here we add PPPoE and modify the Ethernet Type.
        hdr.inner_vlan_tag.eth_type = ETHERTYPE_PPPOES;
        hdr.pppoe.setValid();
        hdr.pppoe.version_type = 0x11;
        hdr.pppoe.code = 8w0; // 0 means session stage.
        hdr.pppoe.session_id = local_metadata.bng.pppoe_session_id;
        c_line_tx.count(local_metadata.bng.line_id);
    }

    action encap_v4() {
        encap();
        hdr.pppoe.length = hdr.ipv4.total_len + 16w1;
        hdr.pppoe.protocol = PPPOE_PROTOCOL_IP4;
    }

    apply {
        // filtering
        ingress_port_vlan.apply();
        fwd_classifier.apply();

        if (local_metadata.skip_forwarding == false) {
            // forwarding
            if (local_metadata.fwd_type == FWD_IPV4_UNICAST) {
                routing_v4.apply();
            }
            next_vlan.apply();
        }

        // First map the double VLAN tags to a line ID
        // If table miss line ID will be 0.
        t_line_map.apply();

        if (hdr.pppoe.isValid()) {
            // upstream
            local_metadata.bng.type = BNG_TYPE_UPSTREAM;
            if(t_pppoe_cp.apply().hit) {
                return;
            }

            if (hdr.ipv4.isValid()) {
                t_pppoe_term_v4.apply();
            }
        } else {
            // downstream
            if (t_line_session_map.apply().hit) {
                if (hdr.ipv4.isValid()) {
                    t_qos_v4.apply();
                }
            }
        }

        if (!ostd.drop) {
            // egress-like processing
            if (local_metadata.push_double_vlan == true) {
		// Double VLAN termination.
                push_outer_vlan();
                push_inner_vlan();
            } else {
                // If no push double vlan, inner_vlan_tag must be popped
                hdr.inner_vlan_tag.setInvalid();
                egress_vlan.apply();
            }

            if (local_metadata.bng.type == (bit<8>) BNG_TYPE_DOWNSTREAM) {
                if (hdr.ipv4.isValid()) {
                    encap_v4();
                }
            }            
        }
    }

}

control egress(inout headers_t hdr, inout local_metadata_t local_metadata, in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) {

    apply {
    }

}

parser egress_parser(packet_in packet, out headers_t hdr, inout local_metadata_t local_metadata, in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta, in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start {
        transition accept;
    }
}

control egress_deparser(packet_out packet, out empty_metadata_t clone_e2e_meta, out empty_metadata_t recirculate_meta, inout headers_t hdr, in local_metadata_t local_metadata, in psa_egress_output_metadata_t istd, in psa_egress_deparser_input_metadata_t edstd) {
    apply {
    }
}


IngressPipeline(packet_parser(), ingress(), packet_deparser()) ip;

EgressPipeline(egress_parser(), egress(), egress_deparser()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
