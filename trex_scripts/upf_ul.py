from trex_stl_lib.api import *
from scapy.contrib.gtp import *

class STLS1(object):


    def create_stream (self,  packet_len):
        size = packet_len - 4
        packet = Ether()/IP(src="172.20.16.99",dst="172.20.16.105")/UDP(dport=2152)/GTP_U_Header(teid=1234)/IP(src="10.10.10.10",dst="192.168.2.21",version=4,id=0xFFFF)/UDP(sport=99,dport=99)
        pad = max(0, size - len(packet)) * 'x'
        pkt = STLPktBuilder(pkt = packet/pad, vm = [])
        return STLStream(packet = pkt, mode = STLTXCont())

    def get_streams (self, direction = 0,  packet_len=64, **kwargs):
        return [ self.create_stream(packet_len) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
