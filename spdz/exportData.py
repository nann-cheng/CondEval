import json

with open("../data/new_emb.txt") as f:
    data = f.read()
ALL_DICT_DATA = json.loads(data)

ALL_LABELS=[]
ALL_RESULTS=[]
fd = open("../data/veri_test.txt",'r')
lines = fd.readlines()
for line in lines:
    item = line.split()
    # print(item)
    ALL_RESULTS.append(1- int(item[0]) )
    ALL_LABELS.append( item[1] )
    ALL_LABELS.append( item[2] )


A_SCALE= int( (1/0.11368578)*(1<<10))
B_SCALE = 1<<10
TRUE_POSITIVE=0

# print(math.sqrt(0.11368578)) = 0.3371732195771188

def write_file(vec,fileName):
    # Write float values to a file
    with open(fileName, 'w+') as f:
        for value in vec:
            f.write(str(value) + ' ')

EXPORT_NUM=1
for index in range(EXPORT_NUM):
    vec_s =  ALL_DICT_DATA[ ALL_LABELS[2*index+1] ]
    write_file(vec_s, "../../../MP-SPDZ/Player-Data/Input-P0-0")

    vec_v =  ALL_DICT_DATA[ ALL_LABELS[2*index] ]
    write_file(vec_v, "../../../MP-SPDZ/Player-Data/Input-P1-0")
    



