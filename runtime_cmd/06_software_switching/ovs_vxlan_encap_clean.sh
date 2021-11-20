ovs-vsctl del-br br0
ip route del 172.168.1.200/32
arp -d 172.168.1.200
