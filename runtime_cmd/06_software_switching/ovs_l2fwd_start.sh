ovs-vsctl del-br br0
ovs-vsctl add-br br0

ovs-vsctl add-port br0 $PORT0_NAME
ovs-vsctl add-port br0 $PORT1_NAME

ovs-ofctl del-flows br0

ovs-ofctl add-flow br0 "eth_dst=$GENERATOR_MAC1, actions=output:$PORT1_NAME"
ovs-ofctl add-flow br0 "eth_dst=$GENERATOR_MAC0, actions=output:$PORT0_NAME"

ovs-ofctl dump-flows br0
