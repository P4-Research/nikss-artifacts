ovs-vsctl del-br br0

ovs-vsctl add-br br0

ovs-vsctl add-port br0 $PORT0_NAME
ovs-vsctl add-port br0 $PORT1_NAME

ovs-ofctl --protocols=OpenFlow15 del-flows br0

#checksum 
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0 actions=resubmit(,1)"

#ingress
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,in_port=PORT0_INDEX actions=push_vlan:0x8100,resubmit(,2)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,in_port=PORT1_INDEX actions=push_vlan:0x8100,resubmit(,2)"

#tbl_routable
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table:2,eth_dst=$DUT_MAC1 actions=resubmit(,3)"

#routing
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,ip,nw_dst=48.0.0.1/24 actions=set_field:$DUT_MAC0>dl_src, set_field:DUT_MAC1->dl_dst, dec_ttl,resubmit(,4)"

#switching
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,dl_dst=$DUT_MAC1,dl_vlan=0 actions=set_field:1->reg0, resubmit(,5)"

#acl
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,nw_src=16.0.0.1,nw_dst=48.0.0.1,tcp,tp_src=80,tp_dst=8080 actions=resubmit(,6)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,nw_src=48.0.0.1,nw_dst=16.0.0.1,tcp,tp_src=8080,tp_dst=80 actions=resubmit(,6)"

#egress
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,dl_vlan=0,vlan_tci=0x1000/0x1fff actions=strip_vlan,pop_vlan, resubmit(,7)"

#end
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7 actions=output:NXM_NX_REG0[]"	
