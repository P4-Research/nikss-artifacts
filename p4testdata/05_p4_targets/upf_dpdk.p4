// Port of upf.p4 to p4-dpdk
// -size of all structure fields must be multiple of 8 bits
// -checksum computations commented out
// -controllers flattened
// -header copy performed field by field

#include <core.p4>
#include "psa.p4"


const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

#define UDP_PORT_GTPU 2152
#define GTP_GPDU 0xff
#define GTPU_VERSION 0x01
#define GTP_PROTOCOL_TYPE_GTP 0x01

typedef bit<8> destination_t;
const destination_t ACCESS = 8w0;
const destination_t CORE = 8w1;
const destination_t SGi_LAN = 8w2;
const destination_t CP_FUNCTION = 8w3;

#define IP_V4_IHL 0x45
const bit<8> DEFAULT_IPV4_TTL = 64;

#define ETH_HDR_SIZE 14
#define IPV4_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define GTP_HDR_SIZE 8



action nop() {
    NoAction();
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv4_t {
    bit<8>    ver_ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<16>   flags_offset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<16> data_offset_res_ecn_ctrl;
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

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header gtpu_t {
    bit<8>  ver_pt_spare_flags;
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32> teid;       /* tunnel endpoint id */
}

struct upf_meta_t {
    bit<64>           seid;    
    bit<32>           far_id; 
    destination_t     src;
    destination_t     dest;
    ip4Addr_t         outer_dst_addr;
    bit<16>           l4_sport;
    bit<16>           l4_dport;
    bit<8>            src_port_range_id; 
    bit<8>            dst_port_range_id; 
    bit<16>           ipv4_len;
    bit<32>           teid;
    bit<32>           gtpu_remote_ip;
    bit<32>           gtpu_local_ip;    
}

struct metadata {
    upf_meta_t upf;
}

struct headers {
    ethernet_t   ethernet;  
    ipv4_t gtpu_ipv4;
    udp_t gtpu_udp;
    gtpu_t gtpu;
    ipv4_t inner_ipv4;
    udp_t inner_udp;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
}

struct empty_t {}

parser IngressParserImpl(packet_in packet,
                         out headers hdr,
                         inout metadata user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_t resubmit_meta,
                         in empty_t recirculate_meta) {
    //InternetChecksum() ck;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // ck.clear();
        // ck.subtract(hdr.ipv4.hdrChecksum);
        // ck.subtract({hdr.ipv4.ttl, hdr.ipv4.protocol });
        // hdr.ipv4.hdrChecksum = ck.get();
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            PROTO_TCP: parse_tcp;
            default: accept;    
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dport) {
             UDP_PORT_GTPU: parse_gtpu;
             default: accept;        
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition parse_inner_ipv4;    
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        // ck.clear();
        // ck.subtract(hdr.inner_ipv4.hdrChecksum);
        // ck.subtract({hdr.ipv4.ttl, hdr.ipv4.protocol });
        // hdr.inner_ipv4.hdrChecksum = ck.get();
        transition select(hdr.inner_ipv4.protocol) {
            PROTO_UDP: parse_inner_udp;
            PROTO_TCP: parse_tcp;
            default: accept;       
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}



control ingress(inout headers hdr,
                inout metadata meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    action set_ingress_dst_port_range_id(bit<8> range_id) {
        meta.upf.dst_port_range_id = range_id;
    }
    action set_ingress_src_port_range_id(bit<8> range_id) {
        meta.upf.src_port_range_id = range_id;
    }
   

    table ingress_l4_dst_port {
        actions = {
            nop;
            set_ingress_dst_port_range_id;
        }
        key = {
            meta.upf.l4_dport: exact; // range macthing unsupported
        }
	    size=512;
    }
    table ingress_l4_src_port {
        actions = {
            nop;
            set_ingress_src_port_range_id;
        }
        key = {
            meta.upf.l4_sport: exact; // range macthing unsupported
        }
    }

    action drop() {
	    ingress_drop(ostd);
    }

    action forward(macAddr_t srcAddr,macAddr_t dstAddr, PortId_t port) {
	    send_to_port(ostd,port);
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key= {
              meta.upf.dest : exact;  
              meta.upf.outer_dst_addr: lpm;
        }
        actions = {
            forward();
            drop();
        }
        const default_action = drop();  
    }

    @hidden
    action gtpu_decap() {
        hdr.gtpu_ipv4.setInvalid();
        hdr.gtpu_udp.setInvalid();
        hdr.gtpu.setInvalid();
        meta.upf.outer_dst_addr=hdr.ipv4.dstAddr;
    }

    action set_seid(bit<64> seid) {
        meta.upf.seid=seid;
    }

    action set_far_id(bit<32> far_id) {
        meta.upf.far_id=far_id;   
    }

    action far_encap_forward(destination_t dest,
                       bit<32> teid,
                       bit<32> gtpu_remote_ip,
                       bit<32> gtpu_local_ip)  {
        meta.upf.dest=dest;                       
        meta.upf.teid = teid;
        meta.upf.gtpu_remote_ip = gtpu_remote_ip;
        meta.upf.gtpu_local_ip = gtpu_local_ip;
        meta.upf.outer_dst_addr=gtpu_remote_ip;                       
    }

    action far_forward(destination_t dest)  {
        meta.upf.dest=dest;    
    }

    action set_source_interface(destination_t src) {
            meta.upf.src=src;
    }


    table source_interface_lookup_by_port {
            key = {
                istd.ingress_port: exact;
            }
            actions = {
                    set_source_interface;
                    @defaultonly nop();
            }
            const default_action = nop();
    }

    table session_lookup_by_ue_ip {
        key = {
            // UE addr for downlink
            hdr.ipv4.dstAddr : exact @name("ipv4_dst");
        }
        actions = {
            set_seid();
            @defaultonly nop();
        }
        const default_action = nop();
    }

    table session_lookup_by_teid {
        key = {
            hdr.gtpu.teid : exact;
        }
        actions = {
            set_seid();    
            nop();
        }
        const default_action = nop();
    }

    table pdr_lookup {
        key= {
            meta.upf.seid:  exact;   
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary; 
            hdr.ipv4.protocol: ternary;
            meta.upf.src_port_range_id: ternary;
            meta.upf.dst_port_range_id: ternary;
            meta.upf.src : exact;   
        }    
        actions = {
            set_far_id();
            @defaultonly drop();
        }
        const default_action = drop();
    }

    table far_lookup {
        key= {
            meta.upf.far_id: exact;
        }    
        actions = {
            far_forward();
            far_encap_forward();
            drop();
        }
        const default_action = drop();   
    }
  
    @hidden
    action gtpu_encap() {
        hdr.gtpu_ipv4.setValid();
        hdr.gtpu_ipv4.ver_ihl = IP_V4_IHL;
        hdr.gtpu_ipv4.diffserv=0;
        hdr.gtpu_ipv4.totalLen = hdr.ipv4.totalLen
                + (IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_SIZE);
        hdr.gtpu_ipv4.identification = 0x1513; 
        hdr.gtpu_ipv4.flags_offset=0;
        hdr.gtpu_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.gtpu_ipv4.protocol = PROTO_UDP;
        hdr.gtpu_ipv4.dstAddr = meta.upf.gtpu_remote_ip;
        hdr.gtpu_ipv4.srcAddr = meta.upf.gtpu_local_ip;
        hdr.gtpu_ipv4.hdrChecksum = 0; // Updated later

        hdr.gtpu_udp.setValid();
        hdr.gtpu_udp.sport = UDP_PORT_GTPU;
        hdr.gtpu_udp.dport = UDP_PORT_GTPU;
        hdr.gtpu_udp.len = meta.upf.ipv4_len
                + (UDP_HDR_SIZE + GTP_HDR_SIZE);
        hdr.gtpu_udp.checksum = 0; 

        hdr.gtpu.setValid();
        hdr.gtpu.ver_pt_spare_flags = (GTPU_VERSION<<5) | (GTP_PROTOCOL_TYPE_GTP<<4);
        hdr.gtpu.msgtype = GTP_GPDU;
        hdr.gtpu.msglen = meta.upf.ipv4_len;
        hdr.gtpu.teid = meta.upf.teid;
    }

    apply {
        if (hdr.gtpu.isValid()) {
            hdr.gtpu_ipv4.ver_ihl=hdr.ipv4.ver_ihl;
            hdr.gtpu_ipv4.diffserv=hdr.ipv4.diffserv;
            hdr.gtpu_ipv4.totalLen=hdr.ipv4.totalLen;
            hdr.gtpu_ipv4.identification=hdr.ipv4.identification;
            hdr.gtpu_ipv4.flags_offset=hdr.ipv4.flags_offset;
            hdr.gtpu_ipv4.ttl=hdr.ipv4.ttl;
            hdr.gtpu_ipv4.protocol=hdr.ipv4.protocol;
            hdr.gtpu_ipv4.dstAddr=hdr.ipv4.dstAddr;
            hdr.gtpu_ipv4.srcAddr=hdr.ipv4.srcAddr;
            hdr.gtpu_ipv4.hdrChecksum=hdr.ipv4.hdrChecksum;

            hdr.ipv4.ver_ihl=hdr.inner_ipv4.ver_ihl;
            hdr.ipv4.diffserv=hdr.inner_ipv4.diffserv;
            hdr.ipv4.totalLen=hdr.inner_ipv4.totalLen;
            hdr.ipv4.identification=hdr.inner_ipv4.identification;
            hdr.ipv4.flags_offset=hdr.inner_ipv4.flags_offset;
            hdr.ipv4.ttl=hdr.inner_ipv4.ttl;
            hdr.ipv4.protocol=hdr.inner_ipv4.protocol;
            hdr.ipv4.dstAddr=hdr.inner_ipv4.dstAddr;
            hdr.ipv4.srcAddr=hdr.inner_ipv4.srcAddr;
            hdr.ipv4.hdrChecksum=hdr.inner_ipv4.hdrChecksum;

            hdr.gtpu_udp.sport=hdr.udp.sport;
            hdr.gtpu_udp.dport=hdr.udp.dport;
            hdr.gtpu_udp.len=hdr.udp.len;
            hdr.gtpu_udp.checksum=hdr.udp.checksum;

            if (hdr.inner_udp.isValid()) {
                hdr.udp.sport=hdr.inner_udp.sport;
                hdr.udp.dport=hdr.inner_udp.dport;
                hdr.udp.len=hdr.inner_udp.len;
                hdr.udp.checksum=hdr.inner_udp.checksum;
            } else {
                hdr.udp.setInvalid();
            }
        }
	    if(hdr.tcp.isValid()) {
		    meta.upf.l4_sport = hdr.tcp.sport;
        	meta.upf.l4_dport = hdr.tcp.dport;
	    } else {
		    meta.upf.l4_sport = hdr.udp.sport;
        	meta.upf.l4_dport = hdr.udp.dport;
	    }
        ingress_l4_src_port.apply();
        ingress_l4_dst_port.apply();

        source_interface_lookup_by_port.apply();    
        if (hdr.gtpu.isValid()) {
            if (session_lookup_by_teid.apply().hit) {
            	gtpu_decap();
            } else {
                ingress_drop(ostd);
	    }
        } else if (!session_lookup_by_ue_ip.apply().hit) {
            return;
        }
        if (pdr_lookup.apply().hit) {
            if (far_lookup.apply().hit) {
                    meta.upf.ipv4_len = hdr.ipv4.totalLen;
            }
        }
        if (meta.upf.dest == ACCESS || meta.upf.dest == CORE) {
            gtpu_encap();
        }

        ipv4_lpm.apply();
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers parsed_hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_t normal_meta,
                        in empty_t clone_i2e_meta,
                        in empty_t clone_e2e_meta)
{
    state start {
        transition accept;
    }

}
control egress(inout headers hdr,
               inout metadata user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}


control IngressDeparserImpl(packet_out packet,
                            out empty_t clone_i2e_meta,
                            out empty_t resubmit_meta,
                            out empty_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    // InternetChecksum() ck;
    apply {
        // if(hdr.gtpu_ipv4.isValid()) {
        //     ck.clear();
        //     ck.add({
        //      hdr.gtpu_ipv4.ver_ihl, hdr.gtpu_ipv4.diffserv,
        //      hdr.gtpu_ipv4.totalLen,
        //      hdr.gtpu_ipv4.identification,
        //      hdr.gtpu_ipv4.flags_offset,
        //      hdr.gtpu_ipv4.ttl, hdr.gtpu_ipv4.protocol,
        //      hdr.gtpu_ipv4.srcAddr,
        //      hdr.gtpu_ipv4.dstAddr});
        //     hdr.gtpu_ipv4.hdrChecksum = ck.get();
        // }
        // ck.clear();
        // ck.subtract(hdr.ipv4.hdrChecksum);
        // ck.add({hdr.ipv4.ttl, hdr.ipv4.protocol });
        // hdr.ipv4.hdrChecksum = ck.get();

        packet.emit(hdr.ethernet);
        packet.emit(hdr.gtpu_ipv4); // only for DL 
        packet.emit(hdr.gtpu_udp);  // only for DL  
        packet.emit(hdr.gtpu);      // only for DL 
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
    }
}

control EgressDeparserImpl(packet_out buffer,
                           out empty_t clone_e2e_meta,
                           out empty_t recirculate_meta,
                           inout headers hdr,
                           in metadata meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
    }
}

IngressPipeline(IngressParserImpl(),
                ingress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               egress(),
               EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;



