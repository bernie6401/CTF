from itertools import product
from pwn import *
from itertools import combinations

root_path = "D:/NTU/CTF/PicoCTF/Crypto/XtraORdinary/"
with open(root_path + 'output.txt', 'r') as f:
    cipher = bytes.fromhex(f.read())

temp_pt = open(root_path + 'temp_plaintext.txt', 'a')


def decrypt(ctxt, key):
    ptxt = b''
    for i in range(len(ctxt)):
        a = ctxt[i]
        b = key[i % len(key)]
        ptxt += bytes([a ^ b])
    return ptxt

def sub_lists (l):
    comb = []
    for i in range(1,len(l)+1):
        comb += [list(j) for j in combinations(l, i)]
    return comb

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]
combos = sub_lists(random_strs)


'''
1st Step - Try to xor all combination of random strings
'''
for i in range(len(combos)):
    tmp_cipher = cipher
    for j in range(len(combos[i])):
        # print(combos[i][j])
        tmp_cipher = decrypt(tmp_cipher, combos[i][j])
    # print()
    print(bytes.fromhex(tmp_cipher.hex()).decode('cp437'))
    temp_pt.writelines(tmp_cipher.hex() + '\n')
temp_pt.close()

'''
2nd Step - Try to find key
'''
key = b'picoCTF{'
cipher = open(root_path + 'temp_plaintext.txt', 'r').readlines()
for i in range(len(cipher)):
    ptxt = decrypt(bytes.fromhex(cipher[i].strip()), key)
    print(bytes.fromhex(ptxt.hex()).decode('cp437'))

'''
3rd Step - Find flag
'''
key = b'Africa!'
cipher = open(root_path + 'temp_plaintext.txt', 'r').readlines()
for i in range(len(cipher)):
    ptxt = decrypt(bytes.fromhex(cipher[i].strip()), key)
    if 'picoCTF{' in bytes.fromhex(ptxt.hex()).decode('cp437'):
        print(f"Flag = {bytes.fromhex(ptxt.hex()).decode('cp437')}")
        break