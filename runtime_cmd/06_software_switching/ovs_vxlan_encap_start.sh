
ovs-vsctl del-br br0

ovs-vsctl add-br br0

ip route add 172.168.1.200/32 dev $PORT1_NAME
arp -s 172.168.1.200 $GENERATOR_MAC1

sudo ovs-vsctl add-port br0 $PORT0_NAME -- set interface $PORT0_NAME ofport_request=10
sudo ovs-vsctl add-port br0 vxlan0 -- set interface vxlan0 type=vxlan options:remote_ip=172.168.1.200  ofport_request=20

sudo ovs-ofctl del-flows br0
sudo ovs-ofctl add-flow br0 in_port=10,actions=output:20


