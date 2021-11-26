from trex_stl_lib.api import *
import argparse


class STLS1(object):

    def create_stream (self, packet_len):

        # Create base packet and pad it to size
        size = packet_len - 4; # HW will add 4 bytes ethernet FCS
        # 00:00:00:00:00:01 is "virtual" router MAC
        base_pkt =  Ether(dst="00:00:00:00:00:01")/IP(src="16.0.0.1",dst="48.0.0.1")/UDP(dport=12,sport=1025)
        pad = max(0, size - len(base_pkt)) * 'x'

        vm = STLScVmRaw( [ STLVmFlowVar(name="mac_src", min_value=1, max_value=1, size=1, op="inc"), # 1 byte varible, range 1-1 ( workaround)
                           STLVmWrFlowVar(fv_name="mac_src", pkt_offset= 11)                           # write it to LSB of SRC offset it 11
                          ]
                       )

        return STLStream(packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXCont( pps=10 ))

    def get_streams (self, packet_len=64, **kwargs):
        # create 1 stream 
        return [ self.create_stream(packet_len) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
