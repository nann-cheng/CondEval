import random
import time

FSS_SEC_PARA = 128
FSS_SEC_PARA_BYTE_LEN = int(FSS_SEC_PARA / 8)

# Could I increase the value of FSS_INPUT_LEN
FSS_INPUT_LEN = 32
FSS_RING_LEN = 1
FSS_RING_BYTE_LEN = int(FSS_RING_LEN + 7 / 8)


def byteArrayXor(a, b):
    # print(type(a))
    # assert type(a) == "bytearray", " a must be of type bytearray"
    # assert type(b) == "bytearray", " b must be of type bytearray"
    # assert len(a) == len(b), "a and b must be of same size"
    result = bytearray(len(a))
    for i in range(len(a)):
        result[i] = a[i] ^ b[i]
    return result


# The resulted fss key length
# FSS_KEY_LENGTH=1462
def sampleBits(seed, expand_len) -> int:
    if seed is None:
        random.seed(time.time())
    else:
        random.seed(seed)
    return random.getrandbits(expand_len)


class GroupElement(object):
    def __init__(self, value, bitlen, repr_value=None):
        assert bitlen >= 1, "Improper bit length or scale"

        self.bitlen = bitlen
        self.Modulo = 2**self.bitlen

        if repr_value is None:
            self.value = (int(value) + 2**self.bitlen) % (2**self.bitlen)
        else:
            self.value = repr_value

    @classmethod
    def unpack(cls, binary, bitlen):
        value = int.from_bytes(binary, "big")
        return GroupElement(value, bitlen)

    def getNegVal(self):
        return 2**self.bitlen - self.value

    def __add__(self, other):
        assert type(other) is GroupElement, "Non groupType"
        assert other.bitlen == self.bitlen, "can only be applied in the same bit length"

        value = (self.value + other.value) & (self.Modulo - 1)
        return GroupElement(value=None, bitlen=self.bitlen, repr_value=value)

    def __sub__(self, other):
        assert type(other) is GroupElement, "Non groupType"
        assert other.bitlen == self.bitlen, "can only be applied in the same bit length"

        value = (self.value - other.value + self.Modulo) & (self.Modulo - 1)
        return GroupElement(value=None, bitlen=self.bitlen, repr_value=value)

    def __gt__(self, other):
        assert type(other) is GroupElement, "Non groupType"
        assert other.bitlen == self.bitlen, "can only be applied in the same bit length"
        return self.value > other.value

    def __lt__(self, other):
        assert type(other) is GroupElement, "Non groupType"
        assert other.bitlen == self.bitlen, "can only be applied in the same bit length"
        return self.value < other.value

    def __eq__(self, other):
        assert type(other) is GroupElement, "Non groupType"
        assert other.bitlen == self.bitlen, "can only be applied in the same bit length"
        return self.value == other.value

    def __getitem__(self, item):
        assert self.bitlen >= item >= 0, f"No index at {item}"
        return self.value >> (self.bitlen - 1 - item) & 1

    def selfPrint(self):
        print("val is: ", self.value)

    def ele2Str(self):
        tmp = ""
        for i in range(self.getLen()):
            tmp += str(self[i])
        return tmp

    def getLen(self):
        return self.bitlen

    def getValue(self):
        return self.value

    def packData(self):
        byteLen = int((self.bitlen + 7) / 8)
        # print("byteLen is: ",byteLen)
        return bytearray(self.value.to_bytes(byteLen, "big"))


class CW_DCF(object):
    def __init__(self, s, v_cw, t_l, t_r):
        self.s = s
        self.v_cw = v_cw
        self.t_l = t_l
        self.t_r = t_r

    def packData(self):
        binary = bytearray(self.s.to_bytes(FSS_SEC_PARA_BYTE_LEN, "big"))
        binary.extend(bytearray(self.v_cw.packData()))
        binary.extend(bytearray(self.t_l.to_bytes(1, "big")))
        binary.extend(bytearray(self.t_r.to_bytes(1, "big")))
        return binary

    @classmethod
    def unpack(cls, binary, ring_len):
        bytes_amount_per_cw = int((ring_len + 7) / 8)

        s = int.from_bytes(binary[:FSS_SEC_PARA_BYTE_LEN], "big")

        new_start = FSS_SEC_PARA_BYTE_LEN
        v_cw = GroupElement.unpack(
            binary[new_start : new_start + bytes_amount_per_cw], ring_len
        )
        new_start += bytes_amount_per_cw
        t_l = int.from_bytes(binary[new_start : new_start + 1], "big")
        new_start += 1
        t_r = int.from_bytes(binary[new_start : new_start + 1], "big")
        return CW_DCF(s, v_cw, t_l, t_r)


class DCFKey(object):
    def __init__(self):
        self.seed = 0
        self.CW_List = []
        self.CW_payload = 0

    def packData(self):
        binary = bytearray(self.seed.to_bytes(FSS_SEC_PARA_BYTE_LEN, "big"))

        binary.extend(bytearray(self.CW_payload.packData()))

        # Allow for at most 2**16 size
        cw_size = len(self.CW_List)
        binary.extend(cw_size.to_bytes(2, "big"))

        for v in self.CW_List:
            binary.extend(bytearray(v.packData()))

        return binary

    @classmethod
    def unpack(cls, binary, ring_len):
        dcfKey = DCFKey()

        bytes_amount_per_cw = int((ring_len + 7) / 8)

        dcfKey.seed = int.from_bytes(binary[:FSS_SEC_PARA_BYTE_LEN], "big")

        end = FSS_SEC_PARA_BYTE_LEN + bytes_amount_per_cw
        dcfKey.CW_payload = GroupElement.unpack(
            binary[FSS_SEC_PARA_BYTE_LEN:end], ring_len
        )

        cw_size = int.from_bytes(binary[end : end + 2], "big")

        new_start = end + 2

        each_cw_len = int(len(binary[new_start:]) / cw_size)

        for i in range(cw_size):
            start = new_start + i * each_cw_len
            end = new_start + (i + 1) * each_cw_len
            dcfKey.CW_List.append(CW_DCF.unpack(binary[start:end], ring_len))
        return dcfKey


class DCF:
    """
    A DCF instantiation input output ring length, a given alpha value, output payload beta
    This functions returns DCF Key for if input < x, payload = 1 currently
    :param x:
    :param inverse: Keep False for unsigned comparison, keep None for signed comparison.
    :param sec_para:
    :param DEBUG:
    :return:
    """

    def __init__(self, sec_para=128, ring_len=32):
        """
        :param sec_para
        :param ring_len: Operation ring length
        :return:
        """
        self.sec_para = sec_para
        # Output ring length
        self.ring_len = ring_len

    def prg(self, seed):
        random.seed(seed)
        return random.getrandbits(4 * self.sec_para + 2)

    def convertG(self, _lambda):
        random.seed(_lambda)
        val = random.getrandbits(self.ring_len)
        return GroupElement(val, self.ring_len)

    def keyGen(self, seed, alpha, beta) -> [DCFKey, DCFKey]:
        """
        This function returns DCF Key, where evaluation output to be "beta" if input < alpha, otherwise output 0
        :param bit_len: Operation group length
        :param alpha: A given alpha value with length may be not the same with output group element
        :param beta:  Desired payload value if input < alpha
        :return:
        """
        # seed_0 belongs to left, seed_1 belongs to right
        seed_bits = sampleBits(seed, self.sec_para * 2)
        seed_0 = seed_bits >> self.sec_para
        seed_1 = seed_bits & ((1 << self.sec_para) - 1)

        k0 = DCFKey()
        k1 = DCFKey()
        k0.seed = seed_0
        k1.seed = seed_1

        t_bits = [0, 1]
        seeds = [seed_0, seed_1]

        V_a = GroupElement(0, self.ring_len)
        zero = GroupElement(0, self.ring_len)

        for i in range(alpha.getLen()):
            prg_res_l = self.prg(seeds[0])
            prg_res_r = self.prg(seeds[1])
            xor_res = prg_res_l ^ prg_res_r
            s_keep = [0, 0]
            t_keep = [0, 0]
            v_keep = [0, 0]

            s_cw, v_cw = 0, GroupElement(0, self.ring_len)
            # Line 10-12
            if alpha[i] == 0:
                s_cw = xor_res >> (self.sec_para + 1) & ((1 << self.sec_para) - 1)
                v0_lose = prg_res_l >> 1 & ((1 << self.sec_para) - 1)
                v1_lose = prg_res_r >> 1 & ((1 << self.sec_para) - 1)
                v_cw = self.convertG(v1_lose) - self.convertG(v0_lose) - V_a
                if t_bits[1] == 1:
                    v_cw = zero - v_cw

                s_keep[0] = prg_res_l >> (3 * self.sec_para + 2)
                s_keep[1] = prg_res_r >> (3 * self.sec_para + 2)
                v_keep[0] = prg_res_l >> (2 * self.sec_para + 2) & (
                    (1 << self.sec_para) - 1
                )
                v_keep[1] = prg_res_r >> (2 * self.sec_para + 2) & (
                    (1 << self.sec_para) - 1
                )
                t_keep[0] = prg_res_l >> (2 * self.sec_para + 1) & 1
                t_keep[1] = prg_res_r >> (2 * self.sec_para + 1) & 1
            else:
                s_cw = xor_res >> (3 * self.sec_para + 2)
                v0_lose = prg_res_l >> (2 * self.sec_para + 2) & (
                    (1 << self.sec_para) - 1
                )
                v1_lose = prg_res_r >> (2 * self.sec_para + 2) & (
                    (1 << self.sec_para) - 1
                )
                v_cw = self.convertG(v1_lose) - self.convertG(v0_lose) - V_a
                if t_bits[1] == 1:
                    v_cw = zero - v_cw
                    v_cw -= beta
                else:
                    v_cw += beta

                s_keep[0] = prg_res_l >> (self.sec_para + 1) & (
                    (1 << self.sec_para) - 1
                )
                s_keep[1] = prg_res_r >> (self.sec_para + 1) & (
                    (1 << self.sec_para) - 1
                )
                v_keep[0] = prg_res_l >> 1 & ((1 << self.sec_para) - 1)
                v_keep[1] = prg_res_r >> 1 & ((1 << self.sec_para) - 1)
                t_keep[0] = prg_res_l & 1
                t_keep[1] = prg_res_r & 1

            # Line 14
            V_a -= self.convertG(v_keep[1])
            V_a += self.convertG(v_keep[0])
            # Line 14:last term addition for V_a
            if t_bits[1] == 1:
                V_a -= v_cw
            else:
                V_a += v_cw

            # Line 15-16
            t_cw_l = (xor_res >> (2 * self.sec_para + 1) & 1) ^ (1 - alpha[i])
            t_cw_r = (xor_res & 1) ^ alpha[i]
            CW = CW_DCF(s_cw, v_cw, t_cw_l, t_cw_r)
            t_cw_keep = t_cw_l
            if alpha[i] == 1:
                t_cw_keep = t_cw_r

            # Line 17-18
            for j in range(2):
                if t_bits[j] == 1:
                    seeds[j] = s_keep[j] ^ s_cw
                    t_bits[j] = t_keep[j] ^ t_cw_keep
                else:
                    seeds[j] = s_keep[j]
                    t_bits[j] = t_keep[j]
            k0.CW_List.append(CW)
            k1.CW_List.append(CW)

        payload = GroupElement(0, self.ring_len)
        if t_bits[1] == 0:
            payload += self.convertG(seeds[1])
            payload -= self.convertG(seeds[0])
            payload -= V_a
        else:
            payload -= self.convertG(seeds[1])
            payload += self.convertG(seeds[0])
            payload += V_a

        k0.CW_payload = payload
        k1.CW_payload = payload
        return k0, k1

    def eval(self, _id, x, key):
        """
        This function evaluates DCF at key with public value x
        :param party:
        :param x: a group element
        :param key:
        :return:
        """
        seed = key.seed
        t_bit = _id

        out = GroupElement(0, self.ring_len)

        levels = len(key.CW_List)
        for i in range(levels):
            # Line 3-4
            cw = key.CW_List[i]
            s_cw = cw.s
            v_cw = cw.v_cw
            t_cw_l = cw.t_l
            t_cw_r = cw.t_r
            prg_res = self.prg(seed)

            # Line 5-6
            s_l = prg_res >> (3 * self.sec_para + 2)
            v_l = prg_res >> (2 * self.sec_para + 2) & ((1 << self.sec_para) - 1)
            t_l = prg_res >> (2 * self.sec_para + 1) & 1

            s_r = prg_res >> (self.sec_para + 1) & ((1 << self.sec_para) - 1)
            v_r = prg_res >> 1 & ((1 << self.sec_para) - 1)
            t_r = prg_res & 1

            if t_bit == 1:
                s_l ^= s_cw
                t_l ^= t_cw_l

                s_r ^= s_cw
                t_r ^= t_cw_r

            # Line 7-10
            if x[i] == 0:
                tmp = self.convertG(v_l)
                if t_bit == 1:
                    tmp += v_cw
                if _id == 1:
                    out -= tmp
                else:
                    out += tmp
                seed = s_l
                t_bit = t_l
            else:
                tmp = self.convertG(v_r)
                if t_bit == 1:
                    tmp += v_cw
                if _id == 1:
                    out -= tmp
                else:
                    out += tmp
                seed = s_r
                t_bit = t_r

        tmp = self.convertG(seed)
        if t_bit == 1:
            tmp += key.CW_payload
        if _id == 1:
            out -= tmp
        else:
            out += tmp

        return out


class NewICKey(object):
    """
    cw_payload0: a arithmetical secret sharing of beta
    cw_payload1: correction word
    dcfKey
    """

    def __init__(self):
        self.CW_0 = 0
        self.CW_1 = 0
        self.dcf_key = DCFKey()

    def packData(self):
        binary = bytearray(self.CW_0.packData())
        binary.extend(self.CW_1.packData())
        binary.extend(self.dcf_key.packData())
        return bytes(binary)

    @classmethod
    def unpack(cls, binary, ring_len):
        # print("len binary is: ",len(binary))

        bytes_amount_per_cw = int((ring_len + 7) / 8)

        binary = bytearray(binary)  # + binary
        icKey = NewICKey()
        icKey.CW_0 = GroupElement.unpack(binary[:bytes_amount_per_cw], ring_len)
        icKey.CW_1 = GroupElement.unpack(
            binary[bytes_amount_per_cw : bytes_amount_per_cw * 2], ring_len
        )
        icKey.dcf_key = DCFKey.unpack(binary[bytes_amount_per_cw * 2 :], ring_len)
        return icKey


class ICNew:
    """
    Interval Containment Test:
        If evaluation input x is \in [0,N/2] return b1, otherwise return b2. (b1,b2 are output group elements)
        (Notice, if b2 is not given, then b2 by default is equal to zero).
    """

    def __init__(self, sec_para=128, ring_len=32):
        self.sec_para = sec_para
        self.ring_len = ring_len

    def keyGen(self, seed, inputLen, b1, b2=None):
        beta = GroupElement(0, self.ring_len)
        addtional_payload = GroupElement(0, self.ring_len)

        if b2 is not None:
            beta = b1 - b2
            # addtional_payload = b2
        else:
            beta = b1

        # Calculate the first correction word
        cw0_0 = GroupElement(sampleBits(None, self.ring_len), self.ring_len)
        cw0_1 = beta - cw0_0

        r_in = GroupElement(sampleBits(None, inputLen), inputLen)
        r_in0 = GroupElement(sampleBits(None, inputLen), inputLen)
        r_in1 = r_in - r_in0

        gamma = GroupElement(-1, inputLen)
        gamma += r_in

        dcf = DCF(sec_para=self.sec_para, ring_len=self.ring_len)
        dcfk0, dcfk1 = dcf.keyGen(seed, gamma, beta)

        # Calculate the second correction word
        alpha_p = r_in
        alpha_q = r_in + GroupElement(1 << (inputLen - 1), inputLen)
        alpha_q_prime = alpha_q + GroupElement(1, inputLen)

        scale = 0
        scale += 1 if alpha_p > alpha_q else 0
        scale -= 1 if alpha_p.getValue() > 0 else 0
        scale += 1 if alpha_q_prime.getValue() > ((1 << (inputLen - 1)) + 1) else 0
        scale += 1 if alpha_q.getValue() == ((1 << inputLen) - 1) else 0

        # print("scale is: ",scale)
        scale *= beta.getValue()
        # To achieve general form of b1,b2 output
        cw_payload = GroupElement(scale, self.ring_len) + addtional_payload

        k0 = NewICKey()
        k0.CW_0 = cw0_0
        k0.dcf_key = dcfk0
        k0.CW_1 = GroupElement(sampleBits(None, self.ring_len), self.ring_len)

        k1 = NewICKey()
        k1.CW_0 = cw0_1
        k1.dcf_key = dcfk1
        k1.CW_1 = cw_payload - k0.CW_1

        return r_in0, r_in1, k0, k1

    # Start the online evaluation phase
    """
    param:: zeta is an masked integer value
    param:: key is an ICNew key
    """

    def eval(self, _id, zeta, key):
        dcf = DCF(sec_para=self.sec_para, ring_len=self.ring_len)

        inputLen = zeta.getLen()

        # start_ = time.time()
        scale = 1 if zeta.getValue() > 0 else 0

        # print("eval scale is: ",scale)
        scale -= 1 if zeta.getValue() > ((1 << (inputLen - 1)) + 1) else 0

        # print("eval scale is: ",scale)

        scale *= key.CW_0.getValue()
        out = GroupElement(scale, self.ring_len)

        x_p = zeta + GroupElement((1 << inputLen) - 1, inputLen)
        x_q_prime = zeta + GroupElement((1 << (inputLen - 1)) - 2, inputLen)

        out -= dcf.eval(_id, x_p, key.dcf_key)
        out += dcf.eval(_id, x_q_prime, key.dcf_key)
        out += key.CW_1

        # print("One ICNew eval cost ",time.time() - start_)
        return out


"""
    Encapsulated CondEvalKey generation and decryption pipeline for input (f,\land) where f is defined by fss key pairs
"""


class CondEval(object):

    """
    fssKeyPairs: any fss key pairs should be [ packed binary bytes ] in byte() state
    _id: evaluation id
    outputs: an pair of encapsulated CondEvalKey
    """

    def __init__(self,ring_len, cipher, sk):
        self.ring_len = ring_len
        self.cipher = cipher
        self.sk = sk

    @classmethod
    def genFromFssKeys(cls, fssKeyPairs):
        permuations = [random.randint(0, 1) for j in range(3)]
        p0, p1, t = permuations[0], permuations[1], permuations[2]

        fssKey_len = len(fssKeyPairs[0])
        ext_fssKey_len = fssKey_len + 1

        sk0_0 = bytearray(
            sampleBits(None, ext_fssKey_len * 8).to_bytes(ext_fssKey_len, "big")
        )
        sk0_1 = bytearray(
            sampleBits(None, ext_fssKey_len * 8).to_bytes(ext_fssKey_len, "big")
        )
        sk1_0 = bytearray(
            sampleBits(None, ext_fssKey_len * 8).to_bytes(ext_fssKey_len, "big")
        )
        sk1_1 = bytearray(
            sampleBits(None, ext_fssKey_len * 8).to_bytes(ext_fssKey_len, "big")
        )

        concatenate_key_t = bytearray(fssKeyPairs[t]).extend(t.to_bytes(1, "big"))
        concatenate_key_not_t = bytearray(fssKeyPairs[1 - t]).extend(
            (1 - t).to_bytes(1, "big")
        )
        m0_0 = byteArrayXor(sk0_0, concatenate_key_t)
        m0_1 = byteArrayXor(sk0_1, concatenate_key_not_t)
        m1_0 = byteArrayXor(sk1_0, concatenate_key_t)
        m1_1 = byteArrayXor(sk1_1, concatenate_key_not_t)

        C0 = [m0_0, m0_1]
        C1 = [m1_0, m1_1]
        if p0 == 1:
            C0 = [m0_1, m0_0]
        if p1 == 1:
            C1 = [m1_1, m1_0]
        SK_0 = ((sk1_0, sk1_1), p1)
        SK_1 = ((sk0_0, sk0_1), p0)

        return [(C0, SK_0), (C1, SK_1)]

    """
    Extract correction decryption key based on the boolean secret sharing a party holds.
    Input:
        boolean_share: 0 or 1 (int)
    Output:
        a byte_array object (will be sent to the other party)
    """

    def getDecryptionKey(self, boolean_share):
        xor_p = int(self.sk[-1]) ^ boolean_share
        sk = self.sk[boolean_share]
        result = bytearray(xor_p.to_bytes(1, "big"))
        return result.extend(sk)

     """
        Upon received other party's message, start the evaluation locally.
        Input:
            boolean_share: 0 or 1 (int)
        Output:
            a byte_array object (will be sent to the other party)
    """
    def evaluate(self, other,ring_ele):
        p = int.from_bytes(other[0], "big")
        cipher = self.cipher[p]
        decrypted = byteArrayXor(cipher, other[1:])

        id = int.from_bytes(decrypted[-1],"big")
        icKey =  NewICKey.unpack( decrypted[:-1], self.ring_len)
        ic = ICNew(ring_len=1)
        return ic.eval(id, ring_ele, icKey)

class FlexKey(object):
    """
    FlexKey defining what's transmited in OT.
    icKey: integer comparison key
    _id: evaluation id
    payload: further addtional correction word, a group element
    """

    def __init__(self, _id, icKey, payload):
        self.id = _id
        self.key = icKey
        self.CW_payload = payload

    """
    Constructing FlexKey from bytearray
    binary: a bytearray object
    """

    @classmethod
    def unpack(cls, binary, ring_len):
        FIX_OUTPUT_BITS_LEN = 96
        bytes_amount_per_cw = int((FIX_OUTPUT_BITS_LEN + 7) / 8)
        # _id = int.from_bytes( binary[:1],"big" )
        id = int.from_bytes(binary[:1], "big")
        CW_payload = GroupElement.unpack(
            binary[1 : bytes_amount_per_cw + 1], FIX_OUTPUT_BITS_LEN
        )
        key = NewICKey.unpack(binary[bytes_amount_per_cw + 1 :], ring_len)
        return FlexKey(id, key, CW_payload)

    def packData(self):
        """
        Byte length for each field
        CW_payload :
        """
        binary = bytearray(self.id.to_bytes(1, "big"))
        binary.extend(bytearray(self.CW_payload.packData()))
        binary.extend(self.key.packData())
        # print("FlexKey len is: ",len(binary))
        return binary
