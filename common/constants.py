import json
from pathlib import Path

# Get the absolute path to the directory where this script is located
parent_location = Path(__file__).resolve().parent.parent

with open(parent_location / "data/new_emb.txt") as f:
    data = f.read()
ALL_DICT_DATA = json.loads(data)

ALL_LABELS = []
ALL_RESULTS = []
# fd = open("data/100_veri.txt",'r')
fd = open(parent_location / "data/veri_test.txt", "r")
lines = fd.readlines()
for line in lines:
    item = line.split()
    # print(item)
    ALL_RESULTS.append(int(item[0]))
    ALL_LABELS.append(item[1])
    ALL_LABELS.append(item[2])
SAMPLE_NUM = len(ALL_RESULTS)


# Each element within the input vector is represented in 64 bits
INPUT_BITS_LEN = 64


"""
Parameter used in the semi-honest protocol:
"""
SEMI_HONEST_MODULO = 1 << INPUT_BITS_LEN


"""
Parameter used in the malicious protocol:
"""
ALPHA_BITS_LEN = 32
AUTHENTICATED_BITS = ALPHA_BITS_LEN + INPUT_BITS_LEN
AUTHENTICATED_MODULO = 1 << AUTHENTICATED_BITS
ALPHA_MODULO = 1 << ALPHA_BITS_LEN


# print(ALL_RESULTS)

"""
This defines the desired circuit topology, which computes the cosine similarity between two non-normalized vectors S and V under the malicious setting.   
"""
CIRCUIT_TOPOLOGY_4_MALICIOUS = [
    "mask_vec_s",  # masked client input data
    "mask_vec_v",  # Masked bank input data
    "alpha",
    "in_s",
    "in_v",  # Input wire random offset
    "s_v",
    "s_s",
    "v_v",  # Beaver's triples for innerproduct
    "ip_out",
    "fss1",  # xy inner product output wire random offset
    "ss_out",
    "vv_out",  # ss, vv inner product output wire random offset
    "ip2",
    "sv_mul",  # Associated beaver's triple for previous output offsets
    "sub_Truncate",  # The random offsets associated with truncation & fss2 random offset
    "fss2",
]

"""
This defines the desired circuit topology, which computes the cosine similarity between two non-normalized vectors S and V under the semi-honest setting.   
"""
CIRCUIT_TOPOLOGY_4_SEMI_HONEST = [
    "mask_vec_s",  # masked client input data
    "mask_vec_v",  # Masked bank input data
    "in_s",
    "in_v",  # Input wire random offset
    "s_v",  # Beaver's triples for innerproduct
    "s_s",
    "v_v",  # Beaver's triples for innerproduct
    "ip_out",
    "fss1",  # xy inner product output wire random offset
    "ss_out",
    "vv_out",  # ss, vv inner product output wire random offset
    "ip2",
    "sv_mul",  # Associated beaver's triple for previous output offsets
    "sub_Truncate",  # The random offsets associated with truncation & fss2 random offset
    "fss2",
]


"""
This defines the desired circuit topology, which computes the cosine similarity between two non-normalized vectors S and V under the semi-honest setting.   
"""
CIRCUIT_TOPOLOGY_4_NAIVE_SEMI_HONEST = [
    "mask_vec_s",  # masked client input data
    "mask_vec_v",  # Masked bank input data
    "in_s",
    "in_v",  # Input wire random offset
    "s_v",  # Beaver's triples for innerproduct
    "s_s",
    "v_v",  # Beaver's triples for innerproduct
    "ip_out",
    "fss1",  # xy inner product output wire random offset
    "ss_out",
    "vv_out",  # ss, vv inner product output wire random offset
    "ip2",
    "sv_mul",  # Associated beaver's triple for previous output offsets
    "sub_Truncate",  # The random offsets associated with truncation & fss2 random offset
    "fss2",
    "extraBeaver",
]

TRUNCATE_FACTOR = 1 << 32
CONVERSION_FACTOR = 1 << 8

# 11370622
THRESHOLD_TAU_SQUARE = 0.11368578
A_SCALE = int((1 / THRESHOLD_TAU_SQUARE) * (1 << 8))
B_SCALE = CONVERSION_FACTOR

FSS_AMOUNT = 10
FSS_TYPES = [0 for i in range(FSS_AMOUNT)]
# FSS_TYPES = [random.randint(0,1) for i in range(FSS_AMOUNT)]

# Due to this specified circuit, the required random number amount be like following
MAC_CHECK_RAND_AMOUNT = 2 * FSS_AMOUNT + 2


import random, secrets

# ALPHA_VALUE = secrets.randbits(ALPHA_BITS_LEN)

MAC_RAND_VEC = [secrets.randbits(ALPHA_BITS_LEN) for i in range(MAC_CHECK_RAND_AMOUNT)]


"""
Benchmarking variables
"""
BENCHMARK_NETWORK_PORTS = ["61001", "61002"]
BENCHMARK_IPS = ["127.0.0.1", "127.0.0.1"]
# NETWORK_BANK_PORT = "60000"
# NETWORK_CLIENT_PORT = "60005"
BENCHMARK_TESTS_AMOUNT = 1

BENCHMARK_TEST_CORRECTNESS = True
