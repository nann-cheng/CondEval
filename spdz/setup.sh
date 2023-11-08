git config --global credential.helper cache
git config --global credential.helper 'cache --timeout=36000'

# -1) For linux distribution, run pre-requirements below:

sudo apt-get install automake build-essential clang cmake git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm

make -j8 mpir



# then make all binary executables.

# For recent 22.04 systems
make boost
make -j8 Fake-Offline.x spdz2k-party.x




./compile.py abio -R 64 
# (64+48)

# 2) Prepare offline insecure data generation

# {
# 	Online-only benchmarkingls

# 	./Fake-Offline.x <nparties> -Z <bit length k for SPDZ2k> -S <security parameter>

# 	For SPDZ2k, use -Z <k> to set the computation domain to Z_{2^k}, and -S to set the security parameter. The latter defaults to k. At the time of writing, the following combinations are available: 32/32, 64/64, 64/48, and 66/48.

# }
./Fake-Offline.x 2 -Z 64 -S 48

# 3) Online only benchmarking

#Local test
# ./spdz2k-party.x -p 0 -N 2 -F -R 64 -SP 48 -v abio
# ./spdz2k-party.x -p 1 -N 2 -F -R 64 -SP 48 -v abio

./spdz2k-party.x --ip-file-name ipFile.txt -p 0 -N 2 -F -R 64 -SP 48 -v abio
# ./spdz2k-party.x --ip-file-name ipFile.txt -p 1 -N 2 -F -R 64 -SP 48 -v abio


# sudo ip netns exec WAN ./spdz2k-party.x -h 10.0.0.2 -p 0 -N 2 -F -R 64 -SP 48 -v abio
# ./spdz2k-party.x -h 10.0.0.1 -p 1 -N 2 -F -R 64 -SP 48 -v abio

# (proxy client message from 10.0.0.1:5000 to 10.0.0.2:5000)
# socat -v TCP-LISTEN:5000,bind=10.0.0.1,fork,reuseaddr TCP:10.0.0.2:5000
# socat -v TCP-LISTEN:5001,bind=10.0.0.1,fork,reuseaddr TCP:127.0.0.1:5001




# ./spdz2k-party.x -h 10.0.0.1 -p 0 -N 2 -F -R 64 -SP 48 -v abio

# sudo ip netns exec WAN ./spdz2k-party.x -h 10.0.0.1 -p 1 -N 2 -F -R 64 -SP 48 -v abio


# ./spdz2k-party.x -h 10.0.0.1 -N 2 -F -R 64 -SP 48 -v 0 abio



# sudo ip netns exec WAN0 ./spdz2k-party.x --ip-file-name ipFile.txt -p 0 -N 2 -F -R 64 -SP 48 -v abio

# sudo ip netns exec WAN1 ./spdz2k-party.x --ip-file-name ipFile.txt -p 1 -N 2 -F -R 64 -SP 48 -v abio

# ./spdz2k-party.x -ip ipFile.txt -p 1 -N 2 -F -R 64 -SP 48 -v abio


# Verify if it works:

# ./spdz2k-party.x --ip-file-name ipFile.txt -p 0 -N 2 -F -R 64 -SP 48 -v abio
# sudo ip netns exec WAN ./spdz2k-party.x --ip-file-name ipFile.txt -p 1 -N 2 -F -R 64 -SP 48 -v abio



# ./spdz2k-party.x -p 0 -N 2 -F -R 64 -SP 48 -v abio
# ./spdz2k-party.x -p 1 -N 2 -F -R 64 -SP 48 -v abio