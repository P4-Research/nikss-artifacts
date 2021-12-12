ovs-vsctl del-br br0

ovs-vsctl add-br br0

ovs-vsctl add-port br0 $PORT0_NAME -- set interface $PORT0_NAME ofport_request=1
ovs-vsctl add-port br0 $PORT1_NAME -- set interface $PORT1_NAME ofport_request=2

ovs-ofctl --protocols=OpenFlow15 del-flows br0

#checksum 
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0 actions=resubmit(,1)"

#ingress
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,in_port=1 actions=push_vlan:0x8100,resubmit(,2)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,in_port=2 actions=push_vlan:0x8100,resubmit(,2)"

#tbl_routable
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table:2,eth_dst=00:00:00:00:00:01,dl_vlan=0 actions=resubmit(,3)"

#routing
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,ip,nw_dst=10.0.0.2/32 actions=set_field:$DUT_MAC1->dl_src, set_field:$GENERATOR_MAC1->dl_dst, dec_ttl,resubmit(,4)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,ip,nw_dst=10.0.0.1/32 actions=set_field:$DUT_MAC0->dl_src, set_field:$GENERATOR_MAC0->dl_dst, dec_ttl,resubmit(,4)"

#switching
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,dl_dst=$GENERATOR_MAC1,dl_vlan=0 actions=set_field:2->reg0, resubmit(,5)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,dl_dst=$GENERATOR_MAC0,dl_vlan=0 actions=set_field:1->reg0, resubmit(,5)"

#acl
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=0 actions=resubmit(,6)"

#egress
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,reg0=2,dl_vlan=0 actions=strip_vlan,resubmit(,7)"
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,reg0=1,dl_vlan=0 actions=strip_vlan,resubmit(,7)"

#end
sudo ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7 actions=output:NXM_NX_REG0[]"
