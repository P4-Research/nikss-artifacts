#include <core.p4>
#include <psa.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

typedef bit<16> vlan_id_t;
typedef bit<48> ethernet_addr_t;

struct empty_metadata_t {
}

header ethernet_t {
    ethernet_addr_t dst_addr;
    ethernet_addr_t src_addr;
    bit<16>         ether_type;
}

header vlan_tag_t {
    vlan_id_t vlan_id;
    bit<16> eth_type;
}

header ipv4_t {
    bit<8> ver_ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<16>  off_res_ecn_ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header bridged_md_t {
    bit<32> ingress_port;
}

struct headers_t {
    bridged_md_t bridged_meta;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
    ipv4_t ipv4;
    tcp_t  tcp;
    udp_t  udp;
}

struct local_metadata_t {
    bit<16>            l4_sport;
    bit<16>            l4_dport;
}

parser packet_parser(packet_in packet, out headers_t headers, inout local_metadata_t local_metadata, in psa_ingress_parser_input_metadata_t standard_metadata, in empty_metadata_t resub_meta, in empty_metadata_t recirc_meta) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(headers.vlan_tag);
        transition select(headers.vlan_tag.eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(headers.ipv4);

        transition select(headers.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(headers.tcp);
        local_metadata.l4_sport = headers.tcp.sport;
        local_metadata.l4_dport = headers.tcp.dport;
        transition accept;
    }

    state parse_udp {
        packet.extract(headers.udp);
        local_metadata.l4_sport = headers.udp.sport;
        local_metadata.l4_dport = headers.udp.dport;
        transition accept;
    }
}

control packet_deparser(packet_out packet, out empty_metadata_t clone_i2e_meta, out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta, inout headers_t headers, in local_metadata_t local_metadata, in psa_ingress_output_metadata_t istd) {
    apply {
        packet.emit(headers.bridged_meta);
        packet.emit(headers.ethernet);
        packet.emit(headers.vlan_tag);
        packet.emit(headers.ipv4);
        packet.emit(headers.tcp);
        packet.emit(headers.udp);
    }
}

control ingress(inout headers_t headers, inout local_metadata_t local_metadata, in psa_ingress_input_metadata_t standard_metadata,
                inout psa_ingress_output_metadata_t ostd) {

    Counter<bit<32>, bit<32>>(100, PSA_CounterType_t.PACKETS) in_pkts;
    Counter<bit<32>, bit<32>>(100, PSA_CounterType_t.PACKETS) out_pkts;



    action push_vlan(vlan_id_t vlan_id) {
        headers.vlan_tag.setValid();
        headers.vlan_tag.vlan_id = vlan_id;
        headers.vlan_tag.eth_type = headers.ethernet.ether_type;
        headers.ethernet.ether_type = ETHERTYPE_VLAN;
    }

    table tbl_ingress_vlan {

        key = {
            standard_metadata.ingress_port : exact;
        }

        actions = {
            push_vlan;
            NoAction;
        }
    }

    table tbl_routable {
        key = {
            headers.ethernet.dst_addr : exact;
            headers.vlan_tag.vlan_id : exact;
        }

        actions = { NoAction;  }
    }

    action drop() {
        ingress_drop(ostd);
    }

    action set_nexthop(ethernet_addr_t smac, ethernet_addr_t dmac, vlan_id_t vlan_id) {
        // Commented out to satisfy Netperf, low impact on perf
        //headers.ipv4.ttl = headers.ipv4.ttl - 1;
        headers.ethernet.src_addr = smac;
        headers.ethernet.dst_addr = dmac;
        headers.vlan_tag.vlan_id = vlan_id;
    }

    table tbl_routing {
        key = {
            headers.ipv4.dst_addr: lpm;
        }
        actions = {
            set_nexthop;
        }
    }

    action forward(PortId_t output_port) {
        send_to_port(ostd, output_port);
    }

    action broadcast(MulticastGroup_t grp_id) {
        multicast(ostd, grp_id);
    }

    table tbl_switching {
        key = {
            headers.ethernet.dst_addr : exact;
            headers.vlan_tag.vlan_id  : exact;
        }

        actions = {
            forward;
            broadcast;
        }
    }

    table tbl_acl {
        key = {
            headers.ipv4.src_addr : exact;
            headers.ipv4.dst_addr : exact;
            headers.ipv4.protocol : exact;
            local_metadata.l4_sport : exact;
            local_metadata.l4_dport : exact;
        }

        actions = {
            drop;
            NoAction;
        }

        const default_action = NoAction();
    }

    action strip_vlan() {
        headers.ethernet.ether_type = headers.vlan_tag.eth_type;
        headers.vlan_tag.setInvalid();
        out_pkts.count((bit<32>)ostd.egress_port);
    }

    action mod_vlan(vlan_id_t vlan_id) {
        headers.vlan_tag.vlan_id = vlan_id;
        out_pkts.count((bit<32>)ostd.egress_port);
    }

    table tbl_vlan_egress {
        key = {
            ostd.egress_port : exact;
        }

        actions = {
            strip_vlan;
            mod_vlan;
        }

    }

    apply {
        in_pkts.count((bit<32>)standard_metadata.ingress_port);

        tbl_ingress_vlan.apply();
        if (tbl_routable.apply().hit) {
            tbl_routing.apply();
            if (headers.ipv4.ttl == 0) {
                drop();
                exit;
            }
        }
        tbl_switching.apply();
        tbl_acl.apply();
        if (!ostd.drop) {
           tbl_vlan_egress.apply();
        }
    }

}

control egress(inout headers_t headers, inout local_metadata_t local_metadata, in psa_egress_input_metadata_t istd, inout psa_egress_output_metadata_t ostd) {

    apply {
    }
}

parser egress_parser(packet_in buffer, out headers_t headers, inout local_metadata_t local_metadata, in psa_egress_parser_input_metadata_t istd, in empty_metadata_t normal_meta, in empty_metadata_t clone_i2e_meta, in empty_metadata_t clone_e2e_meta) {
    state start {
        transition accept;
    }

}

control egress_deparser(packet_out packet, out empty_metadata_t clone_e2e_meta, out empty_metadata_t recirculate_meta, inout headers_t headers, in local_metadata_t local_metadata, in psa_egress_output_metadata_t istd, in psa_egress_deparser_input_metadata_t edstd) {
    apply {
    }
}


IngressPipeline(packet_parser(), ingress(), packet_deparser()) ip;

EgressPipeline(egress_parser(), egress(), egress_deparser()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
