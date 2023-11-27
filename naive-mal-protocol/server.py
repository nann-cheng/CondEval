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
)
from common.helper import *
from common.constants import *
from constants import CIRCUIT_TOPOLOGY_4_NAIVE_MALICIOUS, RAND_VEC_LEN
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
        self.authen = []

    def get_vec_s(self):
        return self.vec_s

    def get_circuitVal(self, key):
        return self.circuit[key]

    def get_vec_v(self):
        return self.vec_v

    def receiveCircuit(self, all):
        for index, key in enumerate(CIRCUIT_TOPOLOGY_4_NAIVE_MALICIOUS):
            if key.startswith("fss"):
                self.circuit[key] = [
                    NewICKey.unpack(all[index][0], AUTHENTICATED_BITS),
                    NewICKey.unpack(all[index][1], AUTHENTICATED_BITS),
                ]
            else:
                self.circuit[key] = all[index]

        self.vec_s = self.circuit["mask_vec_s"]
        self.vec_v = self.circuit["mask_vec_v"]
        # self.circuit[key] = all[index]
        # print("alpha is: ",self.circuit["alpha"])

    def resetInputWires(self, w0, w1):
        self.in_wire0 = w0
        self.in_wire1 = w1

    def onMulGate(self, keys):
        out_share, out_authen_share = 0, 0
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

            ret = mod_sub(
                ret,
                ring_mul(self.in_wire1, self.circuit[keys[0]][i], AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = mod_sub(
                ret,
                ring_mul(self.in_wire0, self.circuit[keys[1]][i], AUTHENTICATED_MODULO),
                AUTHENTICATED_MODULO,
            )
            ret = ring_add(ret, self.circuit[keys[2]][i], AUTHENTICATED_MODULO)
            if i == 0:
                out_share = ret
            else:
                out_authen_share = ret

        return (out_share, out_authen_share)

    # A local operation realizing FSS offset addition as well as truncation operation
    def sub_Truncate_Fss(self, ipWire, ssWire, vvWire):
        # Step2-1. Square gate
        self.resetInputWires(ipWire, ipWire)
        cur_output = self.onMulGate(["ip_out", "ip_out", "ip2"])
        self.sub_shares.append(cur_output[0])
        self.sub_authen.append(cur_output[1])

        # Step2-2. Mul gate & local sub
        self.resetInputWires(ssWire, vvWire)
        cur_output = self.onMulGate(["ss_out", "vv_out", "sv_mul"])
        self.sub_shares.append(cur_output[0])
        self.sub_authen.append(cur_output[1])

        # a value scaling, b value scaling
        self.sub_shares[0] = ring_mul(A_SCALE, self.sub_shares[0], AUTHENTICATED_MODULO)
        self.sub_shares[1] = ring_mul(B_SCALE, self.sub_shares[1], AUTHENTICATED_MODULO)
        sub = mod_sub(self.sub_shares[0], self.sub_shares[1], AUTHENTICATED_MODULO)

        # Authen: a value scaling, b value scaling
        self.sub_authen[0] = ring_mul(A_SCALE, self.sub_authen[0], AUTHENTICATED_MODULO)
        self.sub_authen[1] = ring_mul(B_SCALE, self.sub_authen[1], AUTHENTICATED_MODULO)
        subAuth = mod_sub(self.sub_authen[0], self.sub_authen[1], AUTHENTICATED_MODULO)

        rnd_wire = self.circuit["sub_Truncate"]
        trunc_share = ring_add(sub, rnd_wire[0], AUTHENTICATED_MODULO)
        self.authen.append(ring_add(subAuth, rnd_wire[1], AUTHENTICATED_MODULO))

        return trunc_share

    def pushNewAuthenShare(self, auth_share):
        self.authen.append(auth_share)

    def onFssCmp(self, maskVal, key):
        ret = []
        ic = ICNew(ring_len=AUTHENTICATED_BITS)
        for i in range(2):
            ret.append(
                ic.eval(
                    self.id, GroupElement(maskVal, FSS_INPUT_LEN), self.circuit[key][i]
                )
            )
        return ret

    # AB-Ab-Ba+ab input_calculation & auth_calculation
    def innerProductWithMulOut(self, keys):
        out_share = None
        # secret input calculation, and authenticated version
        for i in range(2):
            ret = []
            if i == 0:  # Compute normal SS
                if self.id == 0:
                    ret = vec_mul(self.in_wire1, self.in_wire0, AUTHENTICATED_MODULO)
                else:
                    ret = [0] * len(self.in_wire0)
            else:  # Compute on authenticated SS
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

            # Process with random output wire
            new_sum = ring_add(sum, self.circuit[keys[3]][i], AUTHENTICATED_MODULO)
            if i == 0:
                out_share = new_sum
            else:
                self.authen.append(new_sum)
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
        ipRet = self.innerProductWithMulOut(
            ["in_s", "in_v", "s_v", "ip_out"]
        )  # first authen share

        self.resetInputWires(self.vec_s, self.vec_s)
        ssRet = self.onInnerProductGate(
            ["in_s", "in_s", "s_s", "ss_out"]
        )  # second authen share

        self.resetInputWires(self.vec_v, self.vec_v)
        vvRet = self.onInnerProductGate(
            ["in_v", "in_v", "v_v", "vv_out"]
        )  # third authen share
        return [ipRet, ssRet, vvRet]

    def getFinalMac(self, rand_vec, all_partial):
        left, right = 0, 0
        amount = len(rand_vec)

        # print("Debug: the size of self.authen is: ", len(self.authen))

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

    # index = BENCHMARK_TEST_INDEX
    for index in range(BENCHMARK_TESTS_AMOUNT):
        server = Server(_id)

        # For Mac-check use
        all_partial_reveals = []

        rand_vec = [secrets.randbits(ALPHA_BITS_LEN) for i in range(RAND_VEC_LEN)]

        # Step-2: secure computation, Locally load prepared pickle data in setup phase
        share = None
        parent_location = Path(__file__).resolve().parent.parent
        with open(
            parent_location / ("data/offline.pkl" + str(_id) + "-" + str(index)),
            "rb",
        ) as file:
            share = pickle.load(file)
        server.receiveCircuit(share)

        start_time = time.time()
        ################# Round-1 #################
        mShares = server.getFirstRoundMessage()
        # print("mShares: ",mShares)

        if _id == 0:
            otherShares = await pool.recv("server")
            pool.asend("server", mShares)
        else:
            pool.asend("server", mShares)
            otherShares = await pool.recv("server")

        ipWire = ring_add(mShares[0], otherShares[0], AUTHENTICATED_MODULO)
        ssWire = ring_add(mShares[1], otherShares[1], AUTHENTICATED_MODULO)
        vvWire = ring_add(mShares[2], otherShares[2], AUTHENTICATED_MODULO)

        all_partial_reveals.append(ipWire)
        all_partial_reveals.append(ssWire)
        all_partial_reveals.append(vvWire)

        if BENCHMARK_TEST_CORRECTNESS:
            print("Debug-ipWire is: ", ipWire)

        ################# Round-1 #################

        ################# Round-2 #################
        c1_share_pair = server.onFssCmp(ipWire, "fss1")
        mTruncShare = server.sub_Truncate_Fss(ipWire, ssWire, vvWire)

        if _id == 0:
            pool.asend("server", mTruncShare)
            otherTruncShare = await pool.recv("server")
        else:
            otherTruncShare = await pool.recv("server")
            await pool.send("server", mTruncShare)

        reveal4_fss2 = ring_add(
            mTruncShare, otherTruncShare, AUTHENTICATED_MODULO
        )  # fourth authen share

        all_partial_reveals.append(reveal4_fss2)
        finalFssMask = int(reveal4_fss2 / TRUNCATE_FACTOR)
        c2_share_pair = server.onFssCmp(finalFssMask, "fss2")
        ################# Round-2 #################

        ################# Round-3 #################

        if BENCHMARK_TEST_CORRECTNESS:
            m_share = c1_share_pair[0].getValue()
            if _id == 0:
                pool.asend("server", m_share)
                otherShare = await pool.recv("server")
            else:
                otherShare = await pool.recv("server")
                await pool.send("server", m_share)
            print("Debug-c1 is: ", ring_add(m_share, otherShare, AUTHENTICATED_MODULO))

        c1_share = ring_add(
            c1_share_pair[0].getValue(),
            server.get_circuitVal("beaver_a")[0],
            AUTHENTICATED_MODULO,
        )
        c2_share = ring_add(
            c2_share_pair[0].getValue(),
            server.get_circuitVal("beaver_b")[0],
            AUTHENTICATED_MODULO,
        )

        server.pushNewAuthenShare(
            ring_add(
                c1_share_pair[1].getValue(),
                server.get_circuitVal("beaver_a")[1],
                AUTHENTICATED_MODULO,
            )
        )
        server.pushNewAuthenShare(
            ring_add(
                c2_share_pair[1].getValue(),
                server.get_circuitVal("beaver_b")[1],
                AUTHENTICATED_MODULO,
            )
        )

        if _id == 0:
            pool.asend("server", [c1_share, c2_share])
            otherShares = await pool.recv("server")
        else:
            otherShares = await pool.recv("server")
            await pool.send("server", [c1_share, c2_share])
        c1_wire = ring_add(c1_share, otherShares[0], AUTHENTICATED_MODULO)
        c2_wire = ring_add(c2_share, otherShares[1], AUTHENTICATED_MODULO)

        # fifth authen share
        all_partial_reveals.append(c1_wire)

        # sixth authen share
        all_partial_reveals.append(c2_wire)

        server.resetInputWires(c1_wire, c2_wire)

        output_shares = server.onMulGate(["beaver_a", "beaver_b", "beaver_c"])
        ################# Round-3 #################

        # Mac-Verification
        partialMac = server.getFinalMac(rand_vec, all_partial_reveals)
        all_online_time += time.time() - start_time

        if BENCHMARK_TEST_CORRECTNESS:
            if _id == 0:
                other_output = await pool.recv("server")
                await pool.send("server", output_shares[0])
            else:
                await pool.send("server", output_shares[0])
                other_output = await pool.recv("server")

            final_output = ring_add(
                output_shares[0], other_output, AUTHENTICATED_MODULO
            )

            print("The final result is: ", final_output)

            if ALL_RESULTS[index] == final_output:
                print(f"By {index} it is a success!!")
                # TRUE_POSITIVE+=1
                # correctIndexes.append(index)
            else:
                print(f"By {index} it is a mismatch.")

        ################ Return partial values and MAC codes ######
        # await pool.send("bank", [maskEval_shares,partialMac] )
        ################ Return partial values and MAC codes ######
    print("Online time cost is: ", all_online_time / BENCHMARK_TESTS_AMOUNT)
    if _id == 0:
        await pool.shutdown()
    else:
        await pool.shutdown()


if __name__ == "__main__":
    _id = int(sys.argv[1])
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main(_id))
