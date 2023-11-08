from bank import Bank
from server import Server
from common.helper import *
from common.constants import *
from CondEval.libfss.fss import FSS_RING_LEN,GroupElement
import time
import pickle

# Currently using this public channel to display and transfer information
#For Mac-check use
all_partial_reveals=[]

def revealMask(_list):
    global all_partial_reveals
    assert(len(_list)==2)
    mask = ring_add(_list[0],_list[1],AUTHENTICATED_MODULO)
    all_partial_reveals.append(mask)
    return mask

TRUE_POSITIVE=0

offline_consume_time=0
all_online_time=0
verify_consume_time=0


correctIndexes=[]
# PARTIAL_SAMPLE = int(SAMPLE_NUM/1000)
PARTIAL_SAMPLE = SAMPLE_NUM

for index in range(PARTIAL_SAMPLE):
    if index%1000==0:
        print(index, TRUE_POSITIVE)
    all_partial_reveals=[]

    # Offline-Step1: Establish the bank and have the bank generate those corrleated pseudorandomness
    B = Bank(index)
    B.prepCircuit()

    # Offline-Step2: Establish each server and receive corrleated pseudorandomness from the bank
    servers = []
    for i in range(2):
        server = Server(i)
        servers.append(server)
        # Load prepared pickle data
        share=None
        with open('./data/data.pkl'+str(i), 'rb') as file:
            share = pickle.load(file)
        server.receiveCircuit(share)
    # Online-Step1: Input protocol !!Embedded into offline random data!!

    
    # Online-Step2: Online computation
    ################# Round-1 start #################
    start_time = time.time()
    ipRet=[] # Step1-1. inner product gate
    for i in range(2):
        servers[i].resetInputWires(servers[i].get_vec_s(),servers[i].get_vec_v())
        ipRet.append( servers[i].innerProductWithMulOut(["in_s", "in_v", "s_v", "ip_out"]) )

    # Step1-2. Two square gate
    ssShares=[]
    vvShares=[]
    for i in range(2):
        servers[i].resetInputWires(servers[i].get_vec_s(),servers[i].get_vec_s())
        ssShares.append( servers[i].onInnerProductGate(["in_s", "in_s", "s_s", "ss_out"]) )

        servers[i].resetInputWires( servers[i].get_vec_v(),servers[i].get_vec_v() )
        vvShares.append( servers[i].onInnerProductGate(["in_v", "in_v", "v_v", "vv_out"]) )
    
    ipReveals = [ ring_add(a,b,AUTHENTICATED_MODULO) for (a,b) in zip(ipRet[0],ipRet[1])]

    all_partial_reveals.extend(ipReveals)
    ipWire = ipReveals[0]#Use first one for following computation
    ssWire = revealMask(ssShares)
    vvWire = revealMask(vvShares)

    # print("ip wire is:",ipWire)
    # print(all_partial_reveals)
    # print("ss wire is:",ssWire)
    # print("vv wire is:",vvWire)
    ################# Round-1 end#################


    ################# Round-2 start#################
    trunc_masks=[]
    for i in range(2):
        trunc_masks.append( servers[i].sub_Truncate_Fss(ipWire,ssWire,vvWire) )
    sk_Keys=[]
    for i in range(2):
        tmp=[]
        c1Arr = servers[i].onFssCmp(ipReveals,"fss1")
        for j,c1 in enumerate(c1Arr):
            tmp.append( servers[i].getFSS2SK(j,c1) )
        sk_Keys.append( tmp )
        


    for i in range(2):
        servers[i].decryptFSS2Key( sk_Keys[1-i] )

    finalReveals = [ ring_add(a,b,AUTHENTICATED_MODULO) for (a,b) in zip(trunc_masks[0],trunc_masks[1])]
    all_partial_reveals.extend(finalReveals)


    finalFssMask = [ int(a/TRUNCATE_FACTOR) for a in finalReveals]
    # print("real mask truncate value is: ", subWire)
    maskEval_shares=[]
    for i in range(2):
        maskEval_shares.append( [ GroupElement.unpack( v, FSS_RING_LEN) for v in servers[i].onFssCmp(finalFssMask,"fss2") ] )
    finalResults = [ (a+b).getValue() for (a,b) in zip(maskEval_shares[0],maskEval_shares[1])]


    # Final Mac-check Generation
    rand_vec = MAC_RAND_VEC
    
    # vec_add( servers[0].genRandForMacCheck(), servers[1].genRandForMacCheck(),ALPHA_MODULO)

    # print("There are total {} revealed values",len(rand_vec))
    final_val = 0
    for i in range(2):
        final_val = ring_add(final_val, servers[i].getFinalMac(rand_vec, all_partial_reveals),AUTHENTICATED_MODULO)
    ################# Round-2 end#################
    all_online_time += time.time()-start_time

    
    ################# Mac Check & output revealation #################
    # print("final_val is: ",final_val)
    if final_val == 0:
        # print("Mac Verification pass!\n\n")
        lessThan = B.verifyFssResult(finalResults)
        # print("index is: ",index)
        if ALL_RESULTS[index] == lessThan:
            # print("label: ",ALL_RESULTS[index],"  lessThan: ",lessThan)
            TRUE_POSITIVE+=1
            correctIndexes.append(index)
        # print("The lessThan result is: ", lessThan)
    else:
        print("Mac Verification failed!\n\n")
    # all_online_time += time.time()-start_time
    #################Mac Check & output revealation #################

print("TRUE_POSITIVE is: ",TRUE_POSITIVE)
print("SAMPLE_NUM is: ",PARTIAL_SAMPLE)
print("TP is: ",TRUE_POSITIVE/PARTIAL_SAMPLE)
print("average time cost is: ", all_online_time/(PARTIAL_SAMPLE*2))

# print(correctIndexes)
# Data to be written
# dictionary = {
#     "test": correctIndexes
# }
# json_object = json.dumps(dictionary, indent=4)
# with open("test1.json", "w") as outfile:
#     outfile.write(json_object)