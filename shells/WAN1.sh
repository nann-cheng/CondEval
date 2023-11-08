sudo ip netns add WAN0
sudo ip netns add WAN1

# 1. Create a veth pair to connect the two virtual Ethernet interfaces:

sudo ip link add veth1 type veth peer name veth2
# (sudo ip link show)
sudo ip link set veth1 netns WAN0
sudo ip link set veth2 netns WAN1

# 2. Assign IP addresses to the veth interfaces:

sudo ip netns exec WAN0 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec WAN1 ip addr add 10.0.0.2/24 dev veth2
# (sudo ip netns exec WAN0 ifconfig)

# 3. Bring up the interfaces:

# sudo ip link set veth1 up
sudo ip netns exec WAN0 ip link set veth1 up
sudo ip netns exec WAN1 ip link set veth2 up

# 4. Set up traffic control to simulate WAN latency, bandwidth limitations, or packet loss. The following example sets up a 100ms latency between the two virtual Ethernet interfaces:

sudo ip netns exec WAN0 tc qdisc add dev veth1 root netem delay 5ms rate 320mbit loss 1%
sudo ip netns exec WAN1 tc qdisc add dev veth2 root netem delay 5ms rate 320mbit loss 1%

# 5. Test the connection.

sudo ip netns exec WAN0 ping 10.0.0.2
sudo ip netns exec WAN1 ping 10.0.0.1
