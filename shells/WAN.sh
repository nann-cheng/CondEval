sudo ip netns add WAN

# 1. Create a veth pair to connect the two virtual Ethernet interfaces:

sudo ip link add veth1 type veth peer name veth2
# (sudo ip link show)
sudo ip link set veth2 netns WAN

# 2. Assign IP addresses to the veth interfaces:

sudo ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec WAN ip addr add 10.0.0.2/24 dev veth2
# (sudo ip netns exec WAN ifconfig)

# 3. Bring up the interfaces:

sudo ip link set veth1 up
sudo ip netns exec WAN ip link set veth2 up

# 4. Set up traffic control to simulate WAN latency, bandwidth limitations, or packet loss. The following example sets up a 10ms latency between the two virtual Ethernet interfaces:

sudo tc qdisc add dev veth1 root netem delay 5ms rate 320mbit loss 1%
sudo ip netns exec WAN tc qdisc add dev veth2 root netem delay 5ms rate 320mbit loss 1%

# 5. Test the connection.

# ping -I veth1 10.0.0.2
sudo ip netns exec WAN ping -I 10.0.0.2 veth1