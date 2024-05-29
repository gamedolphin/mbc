ip link add br0 type bridge mcast_snooping 1 mcast_router 2
ip netns add ns1
ip link add veth1 type veth peer name veth
ip link set veth netns ns1
ip link set dev veth1 master br0
ip netns add ns2
ip link add veth2 type veth peer name veth
ip link set veth netns ns2
ip link set dev veth2 master br0
ip addr add 10.0.0.1/24 brd + dev br0
ip link set br0 up
ip link set veth1 up
ip link set veth2 up
ip netns exec ns1 ip addr add 10.0.0.2/24 brd + dev veth
ip netns exec ns2 ip addr add 10.0.0.3/24 brd + dev veth
ip -all netns exec ip link set lo up
ip -all netns exec ip link set veth up
