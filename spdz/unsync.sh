
# 0) change CONFIG.mine, adapt it to insecure offline generation and specify ring size used in virtual machine

# MY_CFLAGS = -DINSECURE
# MOD = -DRING_SIZE=112 (If 112 is required)

cp CONFIG.mine ../../../MP-SPDZ/CONFIG.mine


# 1) prepare tasks, in which specifying parameters, \ie computation modulo ring 112.
# Specify truncation parameter, float number representation length in

# eg., for fix integer of length 64, where there are 7 bits of decimal part

# sfix.set_precision(7, 57)
# cfix.set_precision(7, 57)

python3 exportData.py
cp abio.mpc ../../../MP-SPDZ/Programs/Source/abio.mpc
cp ipFile.txt ../../../MP-SPDZ/ipFile.txt

# cp setup.sh ../../../MP-SPDZ/setup.sh
# cd ../../../MP-SPDZ/
# ./setup.sh


