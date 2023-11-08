import sys
from pathlib import Path

# Calculate the path to the root of the project
root_path = Path(__file__).parent.parent
sys.path.append(str(root_path))
from libfss.fss import (
    FSS_INPUT_LEN,
    FSS_RING_LEN,
    GroupElement,
    ICNew,
    NewICKey,
    FlexKey,
)
from common.helper import *
from common.constants import *
import secrets

import time
import sys
import asyncio
from tno.mpc.communication import Pool
import pickle


class Server:
    """A description of what the computing server does.
    1) It performs computation as decribed by a predefined circuit f.
    """

    def __init__(self, _id):
        self.id = _id
        self.circuit = {}
        self.sub_shares = []
        self.sub_authen = []

        self.vec_s = None
        self.vec_v = None

        self.in_wire0 = None
        self.in_wire1 = None

        self.partials = []
        self.authen = []
        self.ICfss = ICNew(sec_para=128, ring_len=1)
        self.FSS2Key = []
        self.trapProof = GroupElement(0, AUTHENTICATED_BITS)

    def get_vec_s(self):
        return self.vec_s

    def get_circuitVal(self, key):
        return self.circuit[key]

    def get_vec_v(self):
        return self.vec_v

    def receiveCircuit(self, all):
        for index, key in enumerate(CIRCUIT_TOPOLOGY):
            if key == "fss1":
                self.circuit[key] = [
                    NewICKey.unpack(all[index][i], 1) for i in range(FSS_AMOUNT)
                ]
            else:
                self.circuit[key] = all[index]

        self.vec_s = self.circuit["mask_vec_s"]
        self.vec_v = self.circuit["mask_vec_v"]
        # self.circuit[key] = all[index]
        # print("alpha is: ",self.circuit["alpha"])

    # def genRandForMacCheck(self):
    #     # rets=[]

    #     # print("authenticated RAND number is: ",len(self.authen) - FSS_AMOUNT )

    #     # for i in range(MAC_CHECK_RAND_AMOUNT):
    #     #     rets.append( secrets.randbits(ALPHA_BITS) )
    #         # rets.append( 1 )
    #     return [secrets.randbits(ALPHA_BITS) for i in range(MAC_CHECK_RAND_AMOUNT) ]

    # def inputSecretFromBank(self,vals):
    #     self.vec_v = vals

    # def inputSecretS(self,vec_s):
    #     self.vec_s=vec_s
    #     # print("vec_s is: ",self.vec_s)
    #     self.partials.append(vec_s)

    def resetInputWires(self, w0, w1):
        self.in_wire0 = w0
        self.in_wire1 = w1

    def onMulGate(self, keys):
        ret = 0
        out_share = []
        # secret input calculation, and authenticated version
        for i in range(2):
            if i == 0:
                if self.id == 0:
                    ret = ring_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                else:
                    ret = 0
            else:
                ret = ring_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                ret = ring_mul(ret, self.circuit["alpha"], AUTHENTICATED_MODULO)
            if keys[0] == "ip_out":
                ret = mod_sub(
                    ret,
                    ring_mul(
                        self.in_wire1, self.circuit[keys[0]][0][i], AUTHENTICATED_MODULO
                    ),
                    AUTHENTICATED_MODULO,
                )
                ret = mod_sub(
                    ret,
                    ring_mul(
                        self.in_wire0, self.circuit[keys[1]][0][i], AUTHENTICATED_MODULO
                    ),
                    AUTHENTICATED_MODULO,
                )
            else:
                ret = mod_sub(
                    ret,
                    ring_mul(
                        self.in_wire1, self.circuit[keys[0]][i], AUTHENTICATED_MODULO
                    ),
                    AUTHENTICATED_MODULO,
                )
                ret = mod_sub(
                    ret,
                    ring_mul(
                        self.in_wire0, self.circuit[keys[1]][i], AUTHENTICATED_MODULO
                    ),
                    AUTHENTICATED_MODULO,
                )
            ret = ring_add(ret, self.circuit[keys[2]][i], AUTHENTICATED_MODULO)
            if i == 0:
                self.sub_shares.append(ret)
            else:
                self.sub_authen.append(ret)

    # A local operation realizing FSS offset addition as well as truncation operation
    def sub_Truncate_Fss(self, ipWire, ssWire, vvWire):
        # Step2-1. Square gate
        self.resetInputWires(ipWire, ipWire)
        self.onMulGate(["ip_out", "ip_out", "ip2"])

        # Step2-2. Mul gate & local sub
        self.resetInputWires(ssWire, vvWire)
        self.onMulGate(["ss_out", "vv_out", "sv_mul"])

        # a value scaling, b value scaling
        self.sub_shares[0] = ring_mul(A_SCALE, self.sub_shares[0], AUTHENTICATED_MODULO)
        self.sub_shares[1] = ring_mul(B_SCALE, self.sub_shares[1], AUTHENTICATED_MODULO)
        sub = mod_sub(self.sub_shares[0], self.sub_shares[1], AUTHENTICATED_MODULO)

        # Authen: a value scaling, b value scaling
        self.sub_authen[0] = ring_mul(A_SCALE, self.sub_authen[0], AUTHENTICATED_MODULO)
        self.sub_authen[1] = ring_mul(B_SCALE, self.sub_authen[1], AUTHENTICATED_MODULO)
        subAuth = mod_sub(self.sub_authen[0], self.sub_authen[1], AUTHENTICATED_MODULO)

        trunc_masks = []
        for r in self.circuit["sub_Truncate"]:
            trunc_masks.append(ring_add(sub, r[0], AUTHENTICATED_MODULO))
            self.authen.append(ring_add(subAuth, r[1], AUTHENTICATED_MODULO))
        return trunc_masks

    # ipipShares.append( servers[i].onMulGate(["ip_out", "ip_out", "ip2","square_out"]) )

    # \alpha+subTrunc+offset
    def onFinalFssReveal(self, keys, index):
        ret = 0
        out_share = []

        # secret input calculation, and authenticated version
        for i in range(2):
            if i == 1:
                ret = ring_mul(
                    self.in_wire0, self.circuit["alpha"], AUTHENTICATED_MODULO
                )
            else:
                if self.id == 0:
                    ret = self.in_wire0
                else:
                    ret = 0
            ret = mod_sub(ret, self.circuit[keys[0]][2 + i], AUTHENTICATED_MODULO)
            ret = ring_add(ret, self.circuit[keys[1]][index][i], AUTHENTICATED_MODULO)
            ret = ring_add(ret, self.circuit[keys[2]][index][i], AUTHENTICATED_MODULO)
            out_share.append(ret)
        self.authen.append(out_share[1])
        return out_share[0]

    def getFSS2SK(self, index, c1):
        # player1.append( ([bin_flexKey1_0,bin_flexKey1_1],[sk0_0,sk0_1,p0]) )
        keys = self.circuit["fss2"][index][1]
        position = c1.getValue() ^ keys[2]
        key = keys[position]

        # print(type(position))
        # print(type(key))
        return [position, bytes(key)]

    def decryptFSS2Key(self, sk):
        for j in range(FSS_AMOUNT):
            idx = sk[j][0]
            correctKey = bytearray(sk[j][1])
            # Restore FlexKey format from binary cipher
            correctCipher = self.circuit["fss2"][j][0][idx]
            correctBin = byteArrayXor(correctCipher, correctKey)
            # In self.FSS2Key stores FlexKey object
            self.FSS2Key.append(FlexKey.unpack(bytes(correctBin), FSS_RING_LEN))

    def onFssCmp(self, maskVal_vec, key):
        ret = []
        ic = ICNew(ring_len=1)
        if key == "fss1":
            ret.extend(
                [
                    ic.eval(
                        self.id, GroupElement(v, FSS_INPUT_LEN), self.circuit[key][i]
                    )
                    for i, v in enumerate(maskVal_vec)
                ]
            )
        elif key == "fss2":
            for i, v in enumerate(maskVal_vec):
                ret.extend(
                    [
                        bytes(
                            ic.eval(
                                self.FSS2Key[i].id,
                                GroupElement(v, FSS_INPUT_LEN),
                                self.FSS2Key[i].key,
                            ).packData()
                        )
                    ]
                )
                self.trapProof += self.FSS2Key[i].CW_payload

        return ret

    # AB-Ab-Ba+ab input_calculation & auth_calculation
    def innerProductWithMulOut(self, keys):
        out_share = []
        auth_out_share = []
        # secret input calculation, and authenticated version
        for i in range(2):
            ret = []
            if i == 0:
                if self.id == 0:
                    ret = vec_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                else:
                    ret = [0] * len(self.in_wire0)
            else:
                array = vec_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                alphas = [self.circuit["alpha"]] * len(self.in_wire0)
                ret = vec_mul(array, alphas, AUTHENTICATED_MODULO)

            in_s = [v[i] for v in self.circuit[keys[0]]]  # r_a
            in_v = [v[i] for v in self.circuit[keys[1]]]
            s_v = [v[i] for v in self.circuit[keys[2]]]

            ret = vec_sub(
                ret,
                vec_mul(self.in_wire1, in_s, AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = vec_sub(
                ret,
                vec_mul(self.in_wire0, in_v, AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = vec_add(ret, s_v, AUTHENTICATED_MODULO)

            sum = 0
            for v in ret:
                sum = ring_add(sum, v, AUTHENTICATED_MODULO)

            for v in self.circuit[keys[3]]:
                new_sum = ring_add(sum, v[i], AUTHENTICATED_MODULO)
                if i == 0:
                    out_share.append(new_sum)
                else:
                    auth_out_share.append(new_sum)
        self.authen.extend(auth_out_share)
        return out_share

    # AB-Ab-Ba+ab input_calculation & auth_calculation
    def onInnerProductGate(self, keys):
        out_share = []

        # secret input calculation, and authenticated version
        for i in range(2):
            ret = []
            if i == 0:
                if self.id == 0:
                    ret = vec_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                else:
                    ret = [0] * len(self.in_wire0)
            else:
                array = vec_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                alphas = [self.circuit["alpha"]] * len(self.in_wire0)
                ret = vec_mul(array, alphas, AUTHENTICATED_MODULO)

            in_s = [v[i] for v in self.circuit[keys[0]]]  # r_a
            in_v = [v[i] for v in self.circuit[keys[1]]]
            s_v = [v[i] for v in self.circuit[keys[2]]]
            # print("in_wire 1 is: ", self.in_wire1[0])
            # if i==0:
            #     print(self.id, "Non_Authenti share: ",ring_mul(self.in_wire1[0],in_s[0],AUTHENTICATED_MODULO) )#B x r_a
            #     print(self.id, "Non_Authenti r_a: ",in_s[0] )# r_a
            # else:
            #     print(self.id, "Authenticated share: ",ring_mul(self.in_wire1[0],in_s[0],AUTHENTICATED_MODULO) )#Auth(B x r_a)
            #     print(self.id, "Authenticated r_a: ",in_s[0] )#Auth(r_a)

            ret = vec_sub(
                ret,
                vec_mul(self.in_wire1, in_s, AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = vec_sub(
                ret,
                vec_mul(self.in_wire0, in_v, AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = vec_add(ret, s_v, AUTHENTICATED_MODULO)

            sum = 0
            for v in ret:
                sum = ring_add(sum, v, AUTHENTICATED_MODULO)
            sum = ring_add(sum, self.circuit[keys[3]][i], AUTHENTICATED_MODULO)

            out_share.append(sum)
        self.authen.append(out_share[1])
        return out_share[0]

    def getFirstRoundMessage(self):
        self.resetInputWires(self.vec_s, self.vec_v)
        ipRet = self.innerProductWithMulOut(["in_s", "in_v", "s_v", "ip_out"])

        self.resetInputWires(self.vec_s, self.vec_s)
        ssRet = self.onInnerProductGate(["in_s", "in_s", "s_s", "ss_out"])

        self.resetInputWires(self.vec_v, self.vec_v)
        vvRet = self.onInnerProductGate(["in_v", "in_v", "v_v", "vv_out"])
        return [ipRet, ssRet, vvRet]

    def getFinalMac(self, rand_vec, all_partial):
        left, right = 0, 0
        amount = len(rand_vec)

        left_vec = vec_mul(rand_vec, self.authen, AUTHENTICATED_MODULO)
        right_vec = vec_mul(rand_vec, all_partial, AUTHENTICATED_MODULO)

        # print("left_vec",left_vec)
        # print("right_vec",right_vec)

        for i in range(amount):
            left = ring_add(left, left_vec[i], AUTHENTICATED_MODULO)
            right = ring_add(right, right_vec[i], AUTHENTICATED_MODULO)

        right = ring_mul(right, self.circuit["alpha"], AUTHENTICATED_MODULO)
        # print("alpha is: ",self.circuit["alpha"])
        # return right
        # return left

        ret = mod_sub(left, right, AUTHENTICATED_MODULO)
        # ret = GroupElement( mod_sub(left,right,AUTHENTICATED_MODULO), AUTHENTICATED_MODULO)
        return ret


async def async_main(_id):
    # Create the pool for current server.
    pool = Pool()
    pool.add_http_server(addr=BENCHMARK_IPS[_id], port=BENCHMARK_NETWORK_PORTS[_id])
    pool.add_http_client(
        "server", addr=BENCHMARK_IPS[1 - _id], port=BENCHMARK_NETWORK_PORTS[1 - _id]
    )
    # pool.add_http_client("bank", addr="127.0.0.1", port=NETWORK_BANK_PORT)

    all_online_time = 0

    for index in range(TEST_NUM):
        server = Server(_id)

        # For Mac-check use
        all_partial_reveals = []

        # Offline
        rand_vec = MAC_RAND_VEC

        # Step-2: secure computation, Locally load prepared pickle data in setup phase
        share = None
        with open("./data/offline.pkl" + str(_id), "rb") as file:
            share = pickle.load(file)
        server.receiveCircuit(share)

        start_time = time.time()
        ################# Round-1 #################
        mShares = server.getFirstRoundMessage()
        # print("mShares: ",mShares)

        print("Debug-0")

        if _id == 0:
            otherShares = await pool.recv("server")
            pool.asend("server", mShares)
        else:
            pool.asend("server", mShares)
            otherShares = await pool.recv("server")

        print("Debug-1")

        ipReveals = [
            ring_add(a, b, AUTHENTICATED_MODULO)
            for (a, b) in zip(mShares[0], otherShares[0])
        ]
        ipWire = ipReveals[0]  # Use first one for following computation

        ssWire = ring_add(mShares[1], otherShares[1], AUTHENTICATED_MODULO)
        vvWire = ring_add(mShares[2], otherShares[2], AUTHENTICATED_MODULO)

        all_partial_reveals.extend(ipReveals)
        all_partial_reveals.append(ssWire)
        all_partial_reveals.append(vvWire)
        ################# Round-1 #################

        ################# Round-2 #################
        mTruncShare = server.sub_Truncate_Fss(ipWire, ssWire, vvWire)
        # c1Arr = [ v.getValue() for v in server.onFssCmp(ipReveals,"fss1") ]
        sk_Keys = []
        c1Arr = server.onFssCmp(ipReveals, "fss1")
        for j, c1 in enumerate(c1Arr):
            sk_Keys.append(server.getFSS2SK(j, c1))

        if _id == 0:
            pool.asend("server", [mTruncShare, sk_Keys])
            otherTruncShare, otherSk_Keys = await pool.recv("server")
        else:
            otherTruncShare, otherSk_Keys = await pool.recv("server")
            await pool.send("server", [mTruncShare, sk_Keys])

        finalReveals = [
            ring_add(a, b, AUTHENTICATED_MODULO)
            for (a, b) in zip(mTruncShare, otherTruncShare)
        ]
        all_partial_reveals.extend(finalReveals)
        server.decryptFSS2Key(otherSk_Keys)

        finalFssMask = [int(a / TRUNCATE_FACTOR) for a in finalReveals]
        maskEval_shares = server.onFssCmp(finalFssMask, "fss2")

        # Mac-Verification
        partialMac = server.getFinalMac(rand_vec, all_partial_reveals)
        ################# Round-2 #################
        all_online_time += time.time() - start_time

        ################ Return partial values and MAC codes ######
        # await pool.send("bank", [maskEval_shares,partialMac] )
        ################ Return partial values and MAC codes ######
    print("Online time cost is: ", all_online_time / TEST_NUM)
    if _id == 0:
        await pool.shutdown()
    else:
        await pool.shutdown()


if __name__ == "__main__":
    _id = int(sys.argv[1])
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main(_id))
