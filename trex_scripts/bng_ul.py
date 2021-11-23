from trex_stl_lib.api import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.ppp import PPPoE, PPP

class STLS1(object):


    def create_stream (self, packet_len):
        size = packet_len - 4;
        packet = Ether(type=0x8100)/Dot1Q(vlan=10)/Dot1Q(vlan=100)/PPPoE(version=1, type=1, code=0, sessionid=100)/PPP(proto=0x0021)/IP(src="10.10.10.10",dst="192.168.2.21",version=4,id=0xFFFF)/UDP(sport=99,dport=99)
        pad = max(0, size - len(packet)) * 'x'

        pkt = STLPktBuilder(pkt = packet/pad, vm = [])
        return STLStream(packet = pkt, mode = STLTXCont())


    def get_streams (self, direction = 0,  packet_len=64, **kwargs):
        return [ self.create_stream(packet_len) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
