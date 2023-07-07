enc_key = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe"
enc_key_1 = []
jumble_table = {
    0:{'0':'0'},
    2:{'2':'1'},
    4:{'4':'2'},
    6:{'6':'3'},
    8:{'8':'4'},
    10:{'10':'5'},
    12:{'12':'6'},
    14:{'14':'7'},
    1:{'17':'8'},
    3:{'19':'9'},
    5:{'21':'a'},
    7:{'23':'b'},
    9:{'25':'c'},
    11:{'27':'d'},
    13:{'29':'e'},
    15:{'31':'f'},
}

FLAG= ""
def get_flag(str_1):
    if str_1 % 2 == 0:
        return jumble_table[str_1][str(str_1)]
    else:
        return jumble_table[str_1][str(str_1 + 16)]


for i, single_chr in enumerate(enc_key):
    enc_key_1.append(ord(single_chr) - 0x61)
    if i == 0:
        FLAG += get_flag(enc_key_1[-1])

    else:
        tmp = enc_key_1[-1] - enc_key_1[-2]
        if tmp < 0:
            tmp += 16
        FLAG += get_flag(tmp)
print(enc_key_1)
cipher_text = open("./flag.txt", "r").read()
xor_tmp = int(cipher_text, 16) ^ int(FLAG, 16)
print(bytes.fromhex('{:x}'.format(xor_tmp)).decode('utf-8'))