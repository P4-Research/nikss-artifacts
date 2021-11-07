#include <core.p4>
#include <psa.p4>

struct empty_metadata_t {
}

typedef bit<48> ethernet_addr_t;

header ethernet_t {
    ethernet_addr_t dst_addr;
    ethernet_addr_t src_addr;
    bit<16>         ether_type;
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

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

header vxlan_t {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    vxlan_t vxlan;
    ethernet_t inner_ethernet;
}

struct local_metadata_t {
    ethernet_addr_t eth_dst;
}

parser packet_parser(packet_in packet, out headers_t headers, inout local_metadata_t local_metadata, in psa_ingress_parser_input_metadata_t standard_metadata, in empty_metadata_t resub_meta, in empty_metadata_t recirc_meta) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(headers.ethernet);
        local_metadata.eth_dst = headers.ethernet.dst_addr;
        transition parser_ipv4;
    }
    state parser_ipv4 {
        packet.extract(headers.ipv4);
        transition select(headers.ipv4.protocol) {
           17: parse_udp;
           default: accept;
        }
    }
    state parse_udp {
        packet.extract(headers.udp);
        transition select(headers.udp.dst_port) {
            4789: parse_vxlan;
            default: accept;
         }
    }
    state parse_vxlan {
        packet.extract(headers.vxlan);
        transition parse_inner_ethernet;
    }
    state parse_inner_ethernet {
        packet.extract(headers.inner_ethernet);
        local_metadata.eth_dst = headers.inner_ethernet.dst_addr;
	transition accept;
    }

}

control packet_deparser(packet_out packet, out empty_metadata_t clone_i2e_meta, out empty_metadata_t resubmit_meta, out empty_metadata_t normal_meta, inout headers_t headers, in local_metadata_t local_metadata, in psa_ingress_output_metadata_t istd) {
    apply {
        packet.emit(headers.ethernet);
        packet.emit(headers.ipv4);
        packet.emit(headers.udp);
        packet.emit(headers.vxlan);
        packet.emit(headers.inner_ethernet);
    }
}

control ingress(inout headers_t headers, inout local_metadata_t local_metadata, in psa_ingress_input_metadata_t standard_metadata,
                inout psa_ingress_output_metadata_t ostd) {

    action vxlan_decap(PortId_t port_out) {
        headers.ethernet.setInvalid();
        headers.ipv4.setInvalid();
        headers.udp.setInvalid();
        headers.vxlan.setInvalid();
    }

    action vxlan_encap(
            bit<48> ethernet_src_addr,
            bit<48> ethernet_dst_addr,
            bit<32> ipv4_src_addr,
            bit<32> ipv4_dst_addr,
            bit<24> vxlan_vni,
        ) {
            headers.inner_ethernet = header.ethernet;
            headers.ethernet.src_addr = ethernet_src_addr;
            headers.ethernet.dst_addr = ethernet_dst_addr;

            headers.ethernet.ether_type = 0x0800;

            headers.ipv4.setValid();
            headers.ipv4.ver_ihl = 0x45;
            headers.ipv4.diffserv = 0x0;
            headers.ipv4.total_len = headers.ipv4.total_len + 14 + 20 + 8 + 8;
            headers.ipv4.identification = 0x1513; /* From NGIC */
            headers.outer_ipv4.flags_offset = 0x0;
            headers.outer_ipv4.ttl = 64;
            headers.outer_ipv4.protocol = 17;
            headers.outer_ipv4.src_addr = ipv4_src_addr;
            headers.outer_ipv4.dst_addr = ipv4_dst_addr;

            headers.outer_udp.setValid();
            headers.outer_udp.src_port = 15221; // random port
            headers.outer_udp.dst_port = 4789;
            headers.outer_udp.length = headers.ipv4.total_len + (8 + 8 + 14);

            headers.vxlan.setValid();
            headers.vxlan.flags = 0;
            headers.vxlan.reserved = 0;
            headers.vxlan.vni = vxlan_vni;
            headers.vxlan.reserved2 = 0;
        }

    table vteps {
        key = {
            local_metadata.port : exact;
        }
        actions = {
            vxlan_decap;
        }
    }

    action forward(bit<32> port_out) {
	ostd.drop = false;
        ostd.egress_port = (PortId_t)port_out;
    }

    table fwd {
        key = {
            local_metadata.eth_dst : exact;
        }
        actions = {
            forward;
        }
    }

    apply {
        if (headers.vxlan.isValid()) {
            local_metadata.port = standard_metadata.ingress_port;    
        } else {
	    local_metadata.port = standard_metadata.egress_port;
        }
        vteps.apply();
        fwd.apply();
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
