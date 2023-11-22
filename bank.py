from common.helper import *
from common.constants import *
import secrets
from CondEval.libfss.fss import sampleBits,ICNew,GroupElement,FSS_RING_LEN,FSS_INPUT_LEN,FlexKey
import pickle

import asyncio
from tno.mpc.communication import Pool

class MaliciousFSS:
    """
    MaliciousFSS for (LOGICAL AND) computation with a IntCmp comparison result.
    Two types of FSS keys are provided for computing (A and B)
    0. Normal (A and B) keys
    1. Trap keys
    """
    def __init__(self,seed=None,sec_para=128,ring_len=1,fss_amount = 20):
        self.seed = seed
        self.sec_para = sec_para
        self.ring_len = ring_len
        self.refreshSeed()
        # Type 0 <-> normal keys
        # Type 1 <-> trap keys
        self.typesList=FSS_TYPES
        self.encryptKeys=[]
        for i in range(fss_amount):
            # self.typesList.append( random.randint(0,1) )
            tmp=[]
            for j in range(3):
                tmp.append(random.randint(0,1))
            self.encryptKeys.append( tmp )

    def refreshSeed(self):
        seed_bits = sampleBits(self.seed, self.sec_para*2)
        self.seed = seed_bits & ( (1<<self.sec_para) - 1)
        random.seed(self.seed)

    """
    Prepare FSS keys for the evaluation of c1
    """
    def initKeys(self):
        ic = ICNew(sec_para=self.sec_para, ring_len = 1)
        initialKeys = []
        for _type in self.typesList:
            # Refresh self.seed
            self.refreshSeed()

            # Type 0 <-> normal keys, set initial target output to be 1
            # Type 1 <-> trap keys, whatever the input, target output always be 0
            beta = GroupElement(1, 1)
            if _type == 1:
                beta = GroupElement(0, 1)
            r0,r1,k0,k1 = ic.keyGen(self.seed,FSS_INPUT_LEN,beta)
            initialKeys.append( (r0,r1,k0,k1) )
        return initialKeys

    """
    Prepare message pairs for condEval
    """
    def fss2keyGen(self):
        ic = ICNew(sec_para=self.sec_para, ring_len = self.ring_len)

        r_Array = []
        # Message pairs hold by two servers in OT transfer
        player0=[]
        player1=[]

        for i,_type in enumerate(self.typesList):
            self.refreshSeed()
            beta = GroupElement(1, 1)
            if _type == 1:
                beta = GroupElement(0, 1)
            r0,r1,k0,k1 = ic.keyGen(self.seed,FSS_INPUT_LEN,beta, GroupElement(0, 1))
            ickeys=[k0,k1]
            r_Array.append( r0+r1 )

            # Second, prepare OT messages
            FIX_OUTPUT_BITS_LEN = 96
            self.refreshSeed()
            xi_1 = GroupElement( sampleBits(self.seed, FIX_OUTPUT_BITS_LEN), FIX_OUTPUT_BITS_LEN )
            minus_xi_1 = GroupElement( 0, FIX_OUTPUT_BITS_LEN ) - xi_1
            self.refreshSeed()
            xi_2 = GroupElement( sampleBits(self.seed, FIX_OUTPUT_BITS_LEN), FIX_OUTPUT_BITS_LEN )
            minus_xi_2 = GroupElement( 0, FIX_OUTPUT_BITS_LEN ) - xi_2

            ###########Encrypt keys##############
            p0,p1,t = self.encryptKeys[i]
           
            if _type == 0:# Type 0 <-> normal keys
                #Permutation with p0
                idx0 = p0^t
                idx1 = p0^(1-t)

                bin_flexKey0_0 = FlexKey(idx0,ickeys[idx0],xi_1).packData()
                bin_flexKey0_1 = FlexKey(idx1,ickeys[idx1],xi_1).packData()

                #Permutation with p1
                idx0 = p1^t
                idx1 = p1^(1-t)
                bin_flexKey1_0 = FlexKey(idx0,ickeys[idx0],xi_1).packData()
                bin_flexKey1_1 = FlexKey(idx1,ickeys[idx1],xi_1).packData()
            else:# Type 1 <-> trap keys
                #Permutation with p0
                idx0 = p0^t
                idx1 = p0^(1-t)
                bin_flexKey0_0 = FlexKey(idx0,ickeys[idx0],xi_1).packData()
                bin_flexKey0_1 = FlexKey(idx1,ickeys[idx1],xi_2 ).packData()
                
                #Permutation with p1
                idx0 = p1^t
                idx1 = p1^(1-t)
                bin_flexKey1_0 = FlexKey(idx0,ickeys[idx0],minus_xi_1).packData()
                bin_flexKey1_1 = FlexKey(idx1,ickeys[idx1],minus_xi_2).packData()
            
            wholeKeyByteLen = len(bin_flexKey0_0)

            sk0_0 = bytearray( sampleBits(None,wholeKeyByteLen*8).to_bytes(wholeKeyByteLen,'big'))
            c0_0 = byteArrayXor(sk0_0,bin_flexKey0_0)

            sk0_1 = bytearray( sampleBits(None,wholeKeyByteLen*8).to_bytes(wholeKeyByteLen,'big'))
            c0_1 = byteArrayXor(sk0_1,bin_flexKey0_1)

            sk1_0 = bytearray( sampleBits(None,wholeKeyByteLen*8).to_bytes(wholeKeyByteLen,'big'))
            c1_0 = byteArrayXor(sk1_0,bin_flexKey1_0)

            sk1_1 = bytearray( sampleBits(None,wholeKeyByteLen*8).to_bytes(wholeKeyByteLen,'big'))
            c1_1 = byteArrayXor(sk1_1,bin_flexKey1_1)
            
            player0.append( ([c0_0,c0_1],[sk1_0,sk1_1,p1]) )
            player1.append( ([c1_0,c1_1],[sk0_0,sk0_1,p0]) )
        return r_Array,player0,player1
    
class Bank:
    """A implemenation of a central bank's behavior
    1) Firstly it generates pseduorandom correlated randomness according to an specified circuit f.
    2) It performs BatchMacCheck & FSSVerification before accepting the final output.
    """
    def __init__(self,index):
        """Instantiate PRFs to generate random alpha and random offset"""
        
        # v = ALPHA_VALUE
        v = secrets.randbits(ALPHA_BITS_LEN)
        v0 = secrets.randbits(AUTHENTICATED_BITS)
        v1 = mod_sub(v,v0,AUTHENTICATED_MODULO)
        self.alpha = [v,v0,v1]

        self.FSS = MaliciousFSS(seed=1234127,fss_amount = FSS_AMOUNT)
        self.vec_s = convert_raw(ALL_DICT_DATA[ ALL_LABELS[2*index+1] ])
        self.vec_v = convert_raw( ALL_DICT_DATA[ ALL_LABELS[2*index] ] )

    def genAuthen(self,v):
        authen_v = ring_mul(v,self.alpha[0],AUTHENTICATED_MODULO)
        authen_v0 = secrets.randbits(AUTHENTICATED_BITS)
        authen_v1 = mod_sub(authen_v,authen_v0,AUTHENTICATED_MODULO)
        return (authen_v0,authen_v1)

    def getAuthTuple(self,nbits,_len=None):
        if _len is not None:
            ret=[]
            for i in range(_len):
                v = secrets.randbits(nbits)
                v0 = secrets.randbits(AUTHENTICATED_BITS)
                v1 = mod_sub(v,v0,AUTHENTICATED_MODULO)
                authen_v0,authen_v1 = self.genAuthen(v)
                ret.append((v,v0,v1,authen_v0,authen_v1))
            return ret
        else:
            v = secrets.randbits(nbits)
            v0 = secrets.randbits(AUTHENTICATED_BITS)
            v1 = mod_sub(v,v0,AUTHENTICATED_MODULO)
            authen_v0,authen_v1 = self.genAuthen(v)
            return [v,v0,v1,authen_v0,authen_v1]
    
    def genTuple2(self,val):
        v0 = secrets.randbits(AUTHENTICATED_BITS)
        v1 = mod_sub(val,v0,AUTHENTICATED_MODULO)
        authen_v0,authen_v1 = self.genAuthen(val)
        return [val,v0,v1,authen_v0,authen_v1]

    def genTruncateTuple(self,r_Array):
        truncs = []
        for ele in r_Array:
            # first get 32-bit group element value
            v = ring_mul( ele.getValue(),TRUNCATE_FACTOR, AUTHENTICATED_MODULO)
            # print("truncate mask is: ",v)
            v0 = secrets.randbits(AUTHENTICATED_BITS)
            v1 = mod_sub(v,v0,AUTHENTICATED_MODULO)
            authen_v0,authen_v1 = self.genAuthen(v)
            truncs.append( (v,v0,v1,authen_v0,authen_v1) )
        return truncs

    def prepCircuit(self):
        """Return the arithemtical sharing of pseudorandom data for online computation for the given cosine-similarity computation circuit C"""
        vec_len = len(self.vec_v)
        # Prepare-1. For inner-product (s \cdot v) input wire preparation, output wire preparation
        in_s = self.getAuthTuple(INPUT_BITS_LEN, vec_len)
        in_v = self.getAuthTuple(INPUT_BITS_LEN, vec_len)
        in_v_value=[val[0] for val in in_v]
        self.vec_v = vec_add(self.vec_v, in_v_value, AUTHENTICATED_MODULO)

        in_s_value = [v[0] for v in in_s]
        self.vec_s = vec_add(self.vec_s, in_s_value, AUTHENTICATED_MODULO)

        s_v = [ self.genTuple2( ring_mul(in_s[i][0],in_v[i][0],AUTHENTICATED_MODULO) ) for i in range(vec_len)]
        s_s = [ self.genTuple2( ring_mul(in_s[i][0],in_s[i][0],AUTHENTICATED_MODULO)) for i in range(vec_len)]
        v_v = [ self.genTuple2( ring_mul(in_v[i][0],in_v[i][0],AUTHENTICATED_MODULO)) for i in range(vec_len)]


        # initialKeys.append( (r0,r1,k0,k1) )
        # IMPORTANT!! k0,k1 being ic keys
        # MARK: ip_out has been now an array with multiple instances mixed with trap key FSS
        ip_out = []
        fss1keys=[]
        for v in self.FSS.initKeys():
            r = v[0]+ v[1]
            ip_out.append( self.genTuple2(r.getValue()) )
            v2Bin = v[2].packData()
            v3Bin = v[3].packData()
            # print("v2Bin len is: ", len(v2Bin))
            # print("v3Bin len is: ", len(v3Bin))
            fss1keys.append(  (v2Bin, v3Bin) )
        
         ################The 2nd fss offset preparation#################
        r_Array,player0,player1 = self.FSS.fss2keyGen()
        sub_TruncateArr = self.genTruncateTuple(r_Array)
        fss2keys = [player0,player1 ]
        #(v,v0,v1,authen_v0,authen_v1)
        #################The 2nd fss offset preparation#################

        # Prepare-2.1 For square gate (s \cdot s, v \cdot v) square pair preparation
        ss_out = self.getAuthTuple(INPUT_BITS_LEN)
        vv_out = self.getAuthTuple(INPUT_BITS_LEN)

        # square gate, 2-input multiplication, using the first fss random offset
        ip2 = self.genTuple2( ring_mul(ip_out[0][0],ip_out[0][0],AUTHENTICATED_MODULO))
        sv_product = self.genTuple2( ring_mul(ss_out[0],vv_out[0],AUTHENTICATED_MODULO) )
       
        for i in range(2):
            _start = i+1
            server_correlated =[
                # Masked input data of client/bank
                self.vec_s,
                self.vec_v,
                self.alpha[_start],

                ###First circuit layer###
                [(v[_start],v[_start+2]) for v in in_s],
                [(v[_start],v[_start+2]) for v in in_v],

                [(v[_start],v[_start+2]) for v in s_v],
                [(v[_start],v[_start+2]) for v in s_s],
                [(v[_start],v[_start+2]) for v in v_v],

                [(v[_start],v[_start+2]) for v in ip_out],

                [v[i] for v in fss1keys],

                (ss_out[_start],ss_out[_start+2]),
                (vv_out[_start],vv_out[_start+2]),
                
                ###Used in second round###
                (ip2[_start],ip2[_start+2]),
                (sv_product[_start],sv_product[_start+2]),

                #(v,v0,v1,authen_v0,authen_v1)
                [ (e[_start],e[_start+2] ) for e in sub_TruncateArr ],

                fss2keys[i]
            ]
            with open('./data/data.pkl'+str(i), 'wb') as file:
                pickle.dump(server_correlated, file)

    '''
    1: Authentication fail
    0: Authentication success
    '''
    def verifyFssResult(self,results):
        ret=True
        last = None
        # Type 0 <-> normal keys
        # Type 1 <-> trap keys
        for i,_type in enumerate(FSS_TYPES):
            if _type == 1:
                if 0 != results[i]:
                    ret=False
                    break
            else:
                if last is None:
                    last = results[i]
                else:
                    if results[i] != last:
                        ret =False
                        break
        if ret:
            return last
        else:
            print("Error: Returned results from the servers are inconsistent!")
            return -1

async def async_main():
    # Create the pool for current server.
    pool = Pool()
    pool.add_http_server(addr="127.0.0.1", port=NETWORK_BANK_PORT)
    for i in range(2):
        pool.add_http_client("server"+str(i), addr="127.0.0.1", port=BENCHMARK_NETWORK_PORTS[i])
    pool.add_http_client("client", addr="127.0.0.1", port=NETWORK_CLIENT_PORT)
    

    TRUE_POSITIVE=0
    for index in range(BENCHMARK_TESTS_AMOUNT):
        bank = Bank(index)
        bank.prepCircuit()
        # Offline
        for i in range(2):
            await pool.send("server"+str(i), [bank.sendMessage(i), bank.sendMaskedVal()]  )
            # await pool.send("server"+str(i), bank.sendMaskedVal() )

        if index !=0:
            await pool.send("client", "Ready to start online input!")

        # Online: oblivious transfer with servers
        # ot = OnlineOT()
        # for i in range(2):
        #     c2keys = bank.sendOTKeys(i)
        #     maskBits = await pool.recv("server"+str(i) )
        #     # Sender returned masking message pairs
        #     obtains = [ ot.sendMaskedMessages(maskBits[j],c2keys[j][0],c2keys[j][1])  for j in range(FSS_AMOUNT) ]
        #     await pool.send("server"+str(i), obtains)

        ################# Final-Verification #################
        mac_verify = 0
        evalResults=[]
        for i in range(2):
            response = await pool.recv("server"+str(i) )
            mac_verify = ring_add(mac_verify, response[1], AUTHENTICATED_MODULO)
            evalResults.append( [ GroupElement.unpack( v, FSS_RING_LEN) for v in response[0] ])

        finalAuthen = [ (a+b).getValue() for (a,b) in zip(evalResults[0],evalResults[1])]

        if mac_verify == 0:
            # print("Mac Verification pass!\n\n")
            lessThan = bank.verifyFssResult(finalAuthen)
            # print(lessThan)
            # print("index is: ",index)
            if ALL_RESULTS[index] == lessThan:
                # print("label: ",ALL_RESULTS[index],"  lessThan: ",lessThan)
                TRUE_POSITIVE+=1
                # correctIndexes.append(index)
            # print("The lessThan result is: ", lessThan)
        else:
            print("Mac Verification failed!\n\n")
    
    print("TRUE_POSITIVE is: ",TRUE_POSITIVE)
    print("BENCHMARK_TESTS_AMOUNT is: ",BENCHMARK_TESTS_AMOUNT)
    print("TP is: ",TRUE_POSITIVE/BENCHMARK_TESTS_AMOUNT)

    # print("average time cost is: ", all_online_time/PARTIAL_SAMPLE)
    #print("average ot consume time cost is: ", ot_consume_time/PARTIAL_SAMPLE)
        

    ################# Final-Verification #################
    await pool.shutdown()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main())