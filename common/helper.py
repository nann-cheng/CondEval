import random
from common.constants import *
import os

def mod_sub(A,B,Modulo):
    v = A - B
    if v<0:
        v += Modulo
    return v

def ring_add(A, B,Modulo):
    C = A + B
    return  C & (Modulo-1)

def ring_mul(A,B,Modulo):
    C = A*B
    if C<0:
        C += Modulo
    return  C & ( Modulo - 1)

def vec_sub(A,B,Modulo):
    assert len(A) == len(B), "A and B must be of same size"
    size = len(A)
    C=[]
    for i in range(size):
        v = A[i] - B[i]
        if v<0:
            v += Modulo
        C.append(v)
    return C

def vec_add(A, B,Modulo):
    assert len(A) == len(B),"A and B must be of equal size"
    size = len(A)
    C = []
    for i in range(size):
        v = (A[i] + B[i]) & (Modulo-1)
        C.append(v)
    return C

# InnerProduct
def vec_mul(A, B,Modulo):
    assert len(A) == len(B), "A and B must be of same size"

    ret = []
    for i in range(len(A)):
        ret.append( ring_mul(A[i],B[i], Modulo)) 
    return ret

def convert_raw(vec):
    ret=[]
    for v in vec:
        v_int = int(v*CONVERSION_FACTOR)
        if v_int>=0:
            ret.append(v_int)
        else:
            ret.append(AUTHENTICATED_MODULO+v_int)
    return ret

def convertModular(index,val,from_Modulo,to_Modulo):
    absolute = val
    sign=1

    if val > (from_Modulo>>1):
        absolute = from_Modulo - val
        sign=-1

    if absolute > to_Modulo:
        # print("Exceptional index: ",index)
        absolute = absolute%to_Modulo

    if sign==-1:
        return to_Modulo - absolute
    else:
        return absolute

def byteArrayXor(a,b):
    # print(type(a))
    # assert type(a) == "bytearray", " a must be of type bytearray"
    # assert type(b) == "bytearray", " b must be of type bytearray"
    # assert len(a) == len(b), "a and b must be of same size"

    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = a[i] ^ b[i]
    return result