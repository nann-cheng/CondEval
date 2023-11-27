import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from common.helper import *
from common.constants import *
import secrets
from libfss.fss import (
    sampleBits,
    ICNew,
    GroupElement,
    FSS_RING_LEN,
    FSS_INPUT_LEN,
    FlexKey,
)
import pickle


class AuthenticatedFSS:
    """
    AuthenticatedFSS for internval containment gate computation.
    """

    def __init__(self, alpha, seed=None, sec_para=128):
        self.seed = seed
        self.sec_para = sec_para

        ic = ICNew(sec_para=self.sec_para, ring_len=AUTHENTICATED_BITS)
        self.initialKeys = []
        self.inputWires = []

        fss_amounts_required = 2
        for i in range(fss_amounts_required):
            self.refreshSeed()
            beta = GroupElement(1, AUTHENTICATED_BITS)
            authen_beta = GroupElement(alpha, AUTHENTICATED_BITS)

            r0, r1, k0, k1 = ic.keyGen(self.seed, FSS_INPUT_LEN, beta)

            r_Value = (r0 + r1).getValue()

            self.inputWires.append([r_Value, r0.getValue(), r1.getValue()])
            auth_r0, auth_r1, auth_k0, auth_k1 = ic.keyGen(
                self.seed, FSS_INPUT_LEN, authen_beta, given_rand=r_Value
            )
            # Structure of AuthenFSS:[ (r,r0,r1), ((r0,k0,auth_k0),(r1,k1,auth_k1)), ..]
            self.initialKeys.append(
                [
                    # (r0, k0.packData(), auth_k0.packData()),
                    # (r1, k1.packData(), auth_k1.packData()),
                    (k0.packData(), auth_k0.packData()),
                    (k1.packData(), auth_k1.packData()),
                ]
            )

    def refreshSeed(self):
        seed_bits = sampleBits(self.seed, self.sec_para * 2)
        self.seed = seed_bits & ((1 << self.sec_para) - 1)
        random.seed(self.seed)

    """
    Get authenticated FSS keys
    """

    def getFssKeys(self):
        return self.initialKeys

    def getInputWires(self):
        return self.inputWires


class Dealer:
    """A implemenation of a central bank's behavior
    1) Firstly it generates pseduorandom correlated randomness according to an specified circuit f.
    2) It performs BatchMacCheck & FSSVerification before accepting the final output.
    """

    def __init__(self, index):
        """Instantiate PRFs to generate random alpha and random offset"""

        alpha = secrets.randbits(ALPHA_BITS_LEN)
        v0 = secrets.randbits(AUTHENTICATED_BITS)
        v1 = mod_sub(alpha, v0, AUTHENTICATED_MODULO)
        self.alpha = [alpha, v0, v1]

        self.fss = AuthenticatedFSS(alpha, seed=1234127)

        self.vec_s = convert_raw(ALL_DICT_DATA[ALL_LABELS[2 * index + 1]])
        self.vec_v = convert_raw(ALL_DICT_DATA[ALL_LABELS[2 * index]])

        self._index = index

    def genAuthen(self, v):
        authen_v = ring_mul(v, self.alpha[0], AUTHENTICATED_MODULO)
        authen_v0 = secrets.randbits(AUTHENTICATED_BITS)
        authen_v1 = mod_sub(authen_v, authen_v0, AUTHENTICATED_MODULO)
        return (authen_v0, authen_v1)

    def getAuthTuple(self, nbits, _len=None):
        if _len is not None:
            ret = []
            for i in range(_len):
                v = secrets.randbits(nbits)
                v0 = secrets.randbits(AUTHENTICATED_BITS)
                v1 = mod_sub(v, v0, AUTHENTICATED_MODULO)
                authen_v0, authen_v1 = self.genAuthen(v)
                ret.append((v, v0, v1, authen_v0, authen_v1))
            return ret
        else:
            v = secrets.randbits(nbits)
            v0 = secrets.randbits(AUTHENTICATED_BITS)
            v1 = mod_sub(v, v0, AUTHENTICATED_MODULO)
            authen_v0, authen_v1 = self.genAuthen(v)
            return [v, v0, v1, authen_v0, authen_v1]

    def genTuple2(self, val):
        v0 = secrets.randbits(AUTHENTICATED_BITS)
        v1 = mod_sub(val, v0, AUTHENTICATED_MODULO)
        authen_v0, authen_v1 = self.genAuthen(val)
        return [val, v0, v1, authen_v0, authen_v1]

    def genTruncateTuple(self, input_wire):
        # first get 32-bit group element value
        v = ring_mul(input_wire, TRUNCATE_FACTOR, AUTHENTICATED_MODULO)
        # print("truncate mask is: ",v)
        v0 = secrets.randbits(AUTHENTICATED_BITS)
        v1 = mod_sub(v, v0, AUTHENTICATED_MODULO)
        authen_v0, authen_v1 = self.genAuthen(v)
        return (v, v0, v1, authen_v0, authen_v1)

    # Generate offline phase correlated pseudorandom data specifically for circuit C.
    def genOffline(self):
        """Output the arithemtical sharing of pseudorandom data for online computation for the given cosine-similarity computation circuit C"""
        vec_len = len(self.vec_v)
        # Prepare-1. For inner-product (s \cdot v) input wire preparation, output wire preparation
        in_s = self.getAuthTuple(INPUT_BITS_LEN, vec_len)
        in_v = self.getAuthTuple(INPUT_BITS_LEN, vec_len)
        in_v_value = [val[0] for val in in_v]
        self.vec_v = vec_add(self.vec_v, in_v_value, AUTHENTICATED_MODULO)

        in_s_value = [v[0] for v in in_s]
        self.vec_s = vec_add(self.vec_s, in_s_value, AUTHENTICATED_MODULO)

        s_v = [
            self.genTuple2(ring_mul(in_s[i][0], in_v[i][0], AUTHENTICATED_MODULO))
            for i in range(vec_len)
        ]
        s_s = [
            self.genTuple2(ring_mul(in_s[i][0], in_s[i][0], AUTHENTICATED_MODULO))
            for i in range(vec_len)
        ]
        v_v = [
            self.genTuple2(ring_mul(in_v[i][0], in_v[i][0], AUTHENTICATED_MODULO))
            for i in range(vec_len)
        ]

        # IMPORTANT!! k0,k1 being ic keys
        ip_out = self.fss.getInputWires()[0]
        print("Debug- ip_out is : ", ip_out[0])
        ip_out = self.genTuple2(ip_out[0])

        ################The 2nd fss offset preparation#################
        fss2_input_wire = self.fss.getInputWires()[1][0]
        sub_Truncate = self.genTruncateTuple(fss2_input_wire)
        #################The 2nd fss offset preparation#################

        # Prepare-2.1 For square gate (s \cdot s, v \cdot v) square pair preparation
        ss_out = self.getAuthTuple(INPUT_BITS_LEN)
        vv_out = self.getAuthTuple(INPUT_BITS_LEN)

        # square gate, 2-input multiplication, pre-compute the square result of the first fss random offset
        ip2 = self.genTuple2(ring_mul(ip_out[0], ip_out[0], AUTHENTICATED_MODULO))

        sv_product = self.genTuple2(
            ring_mul(ss_out[0], vv_out[0], AUTHENTICATED_MODULO)
        )

        # Third round: Generate last beaver's triple
        beaver_a = self.getAuthTuple(INPUT_BITS_LEN)
        beaver_b = self.getAuthTuple(INPUT_BITS_LEN)
        beaver_c = self.genTuple2(
            ring_mul(beaver_a[0], beaver_b[0], AUTHENTICATED_MODULO)
        )

        for i in range(2):
            _start = i + 1
            server_correlated = [
                # Masked input data of client/bank
                self.vec_s,
                self.vec_v,
                self.alpha[_start],
                ###First circuit layer###
                [(v[_start], v[_start + 2]) for v in in_s],
                [(v[_start], v[_start + 2]) for v in in_v],
                [(v[_start], v[_start + 2]) for v in s_v],
                [(v[_start], v[_start + 2]) for v in s_s],
                [(v[_start], v[_start + 2]) for v in v_v],
                [ip_out[_start], ip_out[_start + 2]],  # ->ip_out
                self.fss.getFssKeys()[0][i],  # ->fss1 keys
                (ss_out[_start], ss_out[_start + 2]),
                (vv_out[_start], vv_out[_start + 2]),
                ###Used in second round###
                (ip2[_start], ip2[_start + 2]),
                (sv_product[_start], sv_product[_start + 2]),
                # (v,v0,v1,authen_v0,authen_v1)
                (sub_Truncate[_start], sub_Truncate[_start + 2]),
                self.fss.getFssKeys()[1][i],  # ->fss2 keys
                ###Used in third round###
                (beaver_a[_start], beaver_a[_start + 2]),
                (beaver_b[_start], beaver_b[_start + 2]),
                (beaver_c[_start], beaver_c[_start + 2]),
            ]

            parent_location = Path(__file__).resolve().parent.parent
            with open(
                parent_location / ("data/offline.pkl" + str(i) +"-"+str(self._index)), "wb"
            ) as file:
                pickle.dump(server_correlated, file)


if __name__ == "__main__":
    for i in range(BENCHMARK_TESTS_AMOUNT):
        dealer = Dealer(i)
        dealer.genOffline()
