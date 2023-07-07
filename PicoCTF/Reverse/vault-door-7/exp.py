enc_flag = [1096770097, 1952395366, 1600270708, 1601398833, 1716808014, 1734293296, 842413104, 1684157793]

FLAG = ""
bin_flag = []

def pad(bin_flag):
    nblock = 32 - (len(bin_flag) % 32)
    return "0" * nblock + bin_flag

for i in range(len(enc_flag)):
    tmp = pad(bin(enc_flag[i])[2:])
    for j in range(4):
        bin_flag.append(tmp[j*8:j*8+8])

        FLAG += bytes.fromhex(hex(int(bin_flag[-1], 2))[2:]).decode('utf-8')

print("picoCTF{"+FLAG+"}")