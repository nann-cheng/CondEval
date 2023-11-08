# import sys
# sys.path.insert(0, '../') # Add the parent directory to the module search path
# from my_module import my_function # Import the function from the parent module


from common.helper import *
from common.constants import *
import math
import time
import json

test_conversion = (1<<7)

def convert_raw(vec):
    # ret=[v*CONVERSION_FACTOR for v in vec]
    ret=[int(v*test_conversion) for v in vec]
    return ret

def innerProduct(s,v):
    _size = len(s)
    ret=0
    for i in range(_size):
        ret += s[i]*v[i]
    return ret

def binaryLen(val):
    print( math.log(val,2) )


correctIndexes=[]

A_SCALE= int( (1/0.11368578)*(1<<10))
B_SCALE = 1<<10
TRUE_POSITIVE=0

start_time = time.time()
TEST_NUM=SAMPLE_NUM
# TEST_NUM=5000
for index in range(TEST_NUM):
    vec_s = ALL_DICT_DATA[ ALL_LABELS[2*index+1] ]
    vec_v = ALL_DICT_DATA[ ALL_LABELS[2*index] ]

    # print("one multiple: ", vec_s[0]*vec_v[0]/CONVERSION_FACTOR)

    # left = innerProduct(vec_s,vec_v)
    # if left<0:
    #     print("Index", index, "Warning: s*v is negative!",left)

    # vec_s=convert_raw(vec_s)
    # vec_v=convert_raw(vec_v)
    left = innerProduct(vec_s,vec_v)
    c1 = (left < 0)
    # print("s-v: ",left)
    left = left*left
    # print("sv*sv: ",left)
    # left = left*A_SCALE



    # right=threshold*threshold
    # print("right-track: ",right)

    right = innerProduct(vec_s,vec_s)
    # print("ss: ",ss)
    # print("right-track: ",right)

    vv=innerProduct(vec_v,vec_v)
    # print("vv: ",vv)
    right=right*vv
    # print("right-track: ",right)

    # right=right*int(0.11368578*test_conversion*test_conversion)

    right=right*0.11368578
    # right=right*B_SCALE

    c2 = (left-right >= 0)

    c = c1 and c2

    # print("right-track: ",binaryLen(right))
    # print("right-track: ",right)
    if left-right <0:
        # print("Index: ",index,": ",1)
        if ALL_RESULTS[index] == 0:
            TRUE_POSITIVE+=1
            correctIndexes.append(index)
    else:
        # print("Index: ",index,": ",0)
        if ALL_RESULTS[index] == 1:
            TRUE_POSITIVE+=1
            correctIndexes.append(index)

print("TRUE_POSITIVE is: ",TRUE_POSITIVE)
# print("SAMPLE_NUM is: ",TEST_NUM)
print("TP is: ",TRUE_POSITIVE/TEST_NUM)

print("average time cost is: ",1000*(time.time()-start_time)/TEST_NUM, "ms")

# print(correctIndexes)



# Data to be written
# dictionary = {
#     "test": correctIndexes
# }
 
# # Serializing json
# json_object = json.dumps(dictionary, indent=4)
 
# # Writing to sample.json
# with open("test.json", "w") as outfile:
#     outfile.write(json_object)