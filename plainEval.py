from common.helper import *
from common.constants import *
import math
import time
import json


def plain_convert_raw(vec):
    ret = []
    for v in vec:
        v_int = int(v * CONVERSION_FACTOR)
        ret.append(v_int)
    return ret


def innerProduct(s, v):
    _size = len(s)
    ret = 0
    for i in range(_size):
        ret += s[i] * v[i]
    return ret


def binaryLen(val):
    print(math.log(val, 2))


correctIndexes = []
TRUE_POSITIVE = 0

start_time = time.time()
# BENCHMARK_TESTS_AMOUNT = SAMPLE_NUM
# BENCHMARK_TESTS_AMOUNT = 20
for index in range(BENCHMARK_TESTS_AMOUNT):
    vec_s = plain_convert_raw(ALL_DICT_DATA[ALL_LABELS[2 * index + 1]])
    vec_v = plain_convert_raw(ALL_DICT_DATA[ALL_LABELS[2 * index]])
    left = innerProduct(vec_s, vec_v)
    c1 = left >= 0
    print("c1: ", index, c1)

    left = left * left
    left = left * (1 / THRESHOLD_TAU_SQUARE)

    right = innerProduct(vec_s, vec_s)
    vv = innerProduct(vec_v, vec_v)
    right = right * vv
    # print("right-track: ",right)
    c2 = left - right >= 0

    print("c2: ", index, c2, "\n")

    c = c1 and c2

    # print("right-track: ",binaryLen(right))
    # print("right-track: ",right)
    if c == ALL_RESULTS[index]:
        TRUE_POSITIVE += 1
        correctIndexes.append(index)

    # if left - right < 0:
    #     # print("Index: ",index,": ",1)
    #     if ALL_RESULTS[index] == 0:
    #         TRUE_POSITIVE += 1
    #         correctIndexes.append(index)
    # else:
    #     # print("Index: ",index,": ",0)
    #     if ALL_RESULTS[index] == 1:
    #         TRUE_POSITIVE += 1
    #         correctIndexes.append(index)

print("Total true positives are ", TRUE_POSITIVE)
# print("SAMPLE_NUM is: ",BENCHMARK_TESTS_AMOUNT)
print("TP is ", TRUE_POSITIVE / BENCHMARK_TESTS_AMOUNT)
print(
    "On average time cost for each evaluation is ",
    1000 * (time.time() - start_time) / BENCHMARK_TESTS_AMOUNT,
    "ms",
)

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
