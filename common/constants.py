import json

with open("/home/crypto/Desktop/overleaf-CondEval/benchmark/data/new_emb.txt") as f:
    data = f.read()
ALL_DICT_DATA = json.loads(data)

ALL_LABELS=[]
ALL_RESULTS=[]
# fd = open("data/100_veri.txt",'r')
fd = open("/home/crypto/Desktop/overleaf-CondEval/benchmark/data/veri_test.txt",'r')
lines = fd.readlines()
for line in lines:
    item = line.split()
    # print(item)
    ALL_RESULTS.append(int(item[0]) )
    ALL_LABELS.append( item[1] )
    ALL_LABELS.append( item[2] )
SAMPLE_NUM = len(ALL_RESULTS)


TEST_NUM = 1

# print(ALL_RESULTS)

CIRCUIT = [ "mask_vec_s", #masked client input data
            "mask_vec_v", #Masked bank input data
            "alpha",
            "in_s","in_v",#Input wire random offset
            "s_v","s_s","v_v",#Beaver's triples for innerproduct
            "ip_out", "fss1",#xy inner product output wire random offset
            "ss_out","vv_out",#ss, vv inner product output wire random offset
            "ip2","sv_mul",# Associated beaver's triple for previous output offsets
            "sub_Truncate",# The random offsets associated with truncation & fss2 random offset 
            "fss2"
            ]

TRUNCATE_FACTOR = 1<<32
CONVERSION_FACTOR = 1<<8

# 11370622
A_SCALE= int( (1/0.11368578)*(1<<8))
B_SCALE = 1<<8

FSS_AMOUNT = 1
FSS_TYPES = [0 for i in range(FSS_AMOUNT)]
# FSS_TYPES = [random.randint(0,1) for i in range(FSS_AMOUNT)]

# Due to this specified circuit, the required random number amount be like following
MAC_CHECK_RAND_AMOUNT = 2*FSS_AMOUNT + 2

ALPHA_BITS = 32
import random,secrets
# ALPHA_VALUE = secrets.randbits(ALPHA_BITS)

MAC_RAND_VEC = [secrets.randbits(ALPHA_BITS) for i in range(MAC_CHECK_RAND_AMOUNT) ]

INPUT_BITS = 64
AUTHENTICATED_BITS = ALPHA_BITS + INPUT_BITS

ALPHA_MODULO = 1<<ALPHA_BITS
INPUT_MODULO = 1<<INPUT_BITS
AUTHENTICATED_MODULO = 1<<AUTHENTICATED_BITS


NETWORK_SERVER_PORTS = ["61001","61002"]
SERVER_IPS = ["10.0.0.1","10.0.0.2"]
NETWORK_BANK_PORT = "60000"
NETWORK_CLIENT_PORT = "60005"