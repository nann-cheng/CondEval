rm 0.txt 1.txt

python3 dealer.py

sudo nohup ip netns exec ns1 python3 server.py 0 >> 0.txt 2>&1 &

sleep 2

sudo nohup ip netns exec ns2 python3 server.py 1 >> 1.txt 2>&1