import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from libfss.fss import (
    FSS_INPUT_LEN,
    FSS_RING_LEN,
    GroupElement,
    ICNew,
    NewICKey,
    CondEval,
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
        self.vec_s = None
        self.vec_v = None

        self.in_wire0 = None
        self.in_wire1 = None
        self.m_CondEval = None

    def receiveCircuit(self, all):
        for index, key in enumerate(CIRCUIT_TOPOLOGY_4_SEMI_HONEST):
            if key == "fss1":
                self.circuit[key] = NewICKey.unpack(all[index], 1)
            else:
                self.circuit[key] = all[index]

        self.vec_s = self.circuit["mask_vec_s"]
        self.vec_v = self.circuit["mask_vec_v"]
        self.m_CondEval = CondEval(1, self.circuit["fss2"][1], self.circuit["fss2"][2])

    def resetInputWires(self, w0, w1):
        self.in_wire0 = w0
        self.in_wire1 = w1

    def onMulGate(self, keys):
        ret = 0
        if self.id == 0:
            ret = ring_mul(self.in_wire1, self.in_wire0, SEMI_HONEST_MODULO)
        else:
            ret = 0
        ret = mod_sub(
            ret,
            ring_mul(self.in_wire1, self.circuit[keys[0]], SEMI_HONEST_MODULO),
            SEMI_HONEST_MODULO,
        )
        ret = mod_sub(
            ret,
            ring_mul(self.in_wire0, self.circuit[keys[1]], SEMI_HONEST_MODULO),
            SEMI_HONEST_MODULO,
        )
        ret = ring_add(ret, self.circuit[keys[2]], SEMI_HONEST_MODULO)
        self.sub_shares.append(ret)

    # A local operation realizing FSS offset addition as well as truncation operation
    def sub_Truncate_Fss(self, ipWire, ssWire, vvWire):
        # Step2-1. Square gate
        self.resetInputWires(ipWire, ipWire)
        self.onMulGate(["ip_out", "ip_out", "ip2"])

        # Step2-2. Mul gate & local sub
        self.resetInputWires(ssWire, vvWire)
        self.onMulGate(["ss_out", "vv_out", "sv_mul"])

        # a value scaling, b value scaling
        self.sub_shares[0] = ring_mul(A_SCALE, self.sub_shares[0], SEMI_HONEST_MODULO)
        self.sub_shares[1] = ring_mul(B_SCALE, self.sub_shares[1], SEMI_HONEST_MODULO)
        sub = mod_sub(self.sub_shares[0], self.sub_shares[1], SEMI_HONEST_MODULO)
        return ring_add(sub, self.circuit["sub_Truncate"], SEMI_HONEST_MODULO)

    def evalFSS2(self, otherSk, revealVal):
        return self.m_CondEval.evaluate(otherSk, revealVal)

    def getFSS2SK(self, c1):
        return self.m_CondEval.getDecryptionKey(c1)

    def onFss1Cmp(self, maskVal):
        ic = ICNew(ring_len=1)
        ret = ic.eval(
            self.id,
            GroupElement(maskVal, FSS_INPUT_LEN),
            self.circuit["fss1"],
        )
        return ret.getValue()

    # AB-Ab-Ba+ab input_calculation & auth_calculation
    def innerProductWithMulOut(self, keys):
        ret = []
        if self.id == 0:
            ret = vec_mul(self.in_wire1, self.in_wire0, SEMI_HONEST_MODULO)
        else:
            ret = [0] * len(self.in_wire0)

        in_s = self.circuit[keys[0]]  # r_a
        in_v = self.circuit[keys[1]]  # r_b
        s_v = self.circuit[keys[2]]  # r_ab

        # -Ba
        ret = vec_sub(
            ret,
            vec_mul(self.in_wire1, in_s, SEMI_HONEST_MODULO),
            SEMI_HONEST_MODULO,
        )
        # -Ab
        ret = vec_sub(
            ret,
            vec_mul(self.in_wire0, in_v, SEMI_HONEST_MODULO),
            SEMI_HONEST_MODULO,
        )
        # +ab
        ret = vec_add(ret, s_v, SEMI_HONEST_MODULO)

        sum = 0
        for v in ret:
            sum = ring_add(sum, v, SEMI_HONEST_MODULO)
        sum = ring_add(sum, self.circuit[keys[3]], SEMI_HONEST_MODULO)
        return sum

    def getFirstRoundMessage(self):
        self.resetInputWires(self.vec_s, self.vec_v)
        ipRet = self.innerProductWithMulOut(["in_s", "in_v", "s_v", "ip_out"])

        self.resetInputWires(self.vec_s, self.vec_s)
        ssRet = self.innerProductWithMulOut(["in_s", "in_s", "s_s", "ss_out"])

        self.resetInputWires(self.vec_v, self.vec_v)
        vvRet = self.innerProductWithMulOut(["in_v", "in_v", "v_v", "vv_out"])
        return [ipRet, ssRet, vvRet]


async def async_main(_id):
    # Create the pool for current server.
    pool = Pool()
    pool.add_http_server(addr=BENCHMARK_IPS[_id], port=BENCHMARK_NETWORK_PORTS[_id])
    pool.add_http_client(
        "server", addr=BENCHMARK_IPS[1 - _id], port=BENCHMARK_NETWORK_PORTS[1 - _id]
    )
    # pool.add_http_client("bank", addr="127.0.0.1", port=NETWORK_BANK_PORT)

    all_online_time = 0

    for index in range(BENCHMARK_TESTS_AMOUNT):
        server = Server(_id)
        # Step-2: secure computation, Locally load prepared pickle data in setup phase
        parent_location = Path(__file__).resolve().parent.parent
        with open(parent_location / ("data/offline.pkl" + str(_id)), "rb") as file:
            share = pickle.load(file)
            server.receiveCircuit(share)

        start_time = time.time()
        ################# Round-1 #################
        mShares = server.getFirstRoundMessage()
        # print("mShares: ", mShares)

        print("Debug-0")
        if _id == 0:
            otherShares = await pool.recv("server")
            pool.asend("server", mShares)
        else:
            pool.asend("server", mShares)
            otherShares = await pool.recv("server")

        ipWire = ring_add(mShares[0], otherShares[0], SEMI_HONEST_MODULO)
        ssWire = ring_add(mShares[1], otherShares[1], SEMI_HONEST_MODULO)
        vvWire = ring_add(mShares[2], otherShares[2], SEMI_HONEST_MODULO)
        ################# Round-1 #################

        ################# Round-2 #################
        mTruncShare = server.sub_Truncate_Fss(ipWire, ssWire, vvWire)
        c1 = server.onFss1Cmp(ipWire)
        sk_Key = bytes(server.getFSS2SK(c1))

        if _id == 0:
            otherTruncShare, otherSk_Key = await pool.recv("server")
            pool.asend("server", [mTruncShare, sk_Key])
        else:
            pool.asend("server", [mTruncShare, sk_Key])
            otherTruncShare, otherSk_Key = await pool.recv("server")

        finalReveal = ring_add(mTruncShare, otherTruncShare, SEMI_HONEST_MODULO)
        finalReveal = GroupElement(int(finalReveal / TRUNCATE_FACTOR), INPUT_BITS_LEN)

        output_share = server.evalFSS2(bytearray(otherSk_Key), finalReveal)
        ################# Round-2 #################
        all_online_time += time.time() - start_time

        ################ Return partial values and MAC codes ######
        # await pool.send("bank", [maskEval_shares,partialMac] )
        ################ Return partial values and MAC codes ######
    print("Online time cost is: ", all_online_time / BENCHMARK_TESTS_AMOUNT)
    await pool.shutdown()
    # if _id == 0:
    #     await pool.shutdown()
    # else:
    #     await pool.shutdown()


if __name__ == "__main__":
    _id = int(sys.argv[1])
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main(_id))
