rm 0.txt 1.txt

python3 dealer.py

nohup python3 server.py 0 >> 0.txt 2>&1 &

python3 server.py 1 >> 1.txt 2>&1