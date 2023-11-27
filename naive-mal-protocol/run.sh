rm 0.txt 1.txt
for index in {0..5}
do
    python3 dealer.py

    nohup python3 server.py 0 $index >> 0.txt 2>&1 &

    python3 server.py 1 $index >> 1.txt 2>&1
done