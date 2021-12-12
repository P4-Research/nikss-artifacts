ip netns add netperf-client
ip netns add netperf-server

ip link set dev ens4f0 netns netperf-client
ip link set dev ens4f1 netns netperf-server

ip netns exec netperf-client ip addr add 10.0.0.1/24 dev ens4f0
ip netns exec netperf-client ip link set dev ens4f0 up
ip netns exec netperf-server ip addr add 10.0.0.2/24 dev ens4f1
ip netns exec netperf-server ip link set dev ens4f1 up

ip netns exec netperf-client arp -s 10.0.0.2 00:00:00:00:00:01
ip netns exec netperf-server arp -s 10.0.0.1 00:00:00:00:00:01

ip netns exec netperf-server netserver -p 5555
