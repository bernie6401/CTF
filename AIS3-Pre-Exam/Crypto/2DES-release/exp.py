# from Crypto.Cipher import DES
from tqdm import trange
from pyDes import des, CBC, PAD_PKCS5


hint_pt = 'AIS3{??????????}'
hint = '118cd68957ac93b269335416afda70e6d79ad65a09b0c0c6c50917e0cee18c93'
iv = b'4149533320e4b889'
key1_table = []
key2_table = []

def encrypt(m, key, iv):
    # des = DES.new(key, DES.MODE_CBC, iv)
    k = des("0" * 8, CBC, "0"*8, pad=None, padmode=PAD_PKCS5)
    k.setKey(key)
    k.setIV(iv)
    return k.encrypt(m, padmode=PAD_PKCS5)

def decrypt(c, key, iv):
    # des = DES.new(key, DES.MODE_CBC, iv)
    k = des("0" * 8, CBC, "0"*8, pad=None, padmode=PAD_PKCS5)
    k.setKey(key)
    k.setIV(iv)
    return k.decrypt(c, padmode=PAD_PKCS5)

key1 = key2 = '{0:0>16x}'.format(0).encode()
for idx in range(2**32):
    key1_table.append(encrypt(hint_pt, key1, iv))
    key2_table.append(decrypt(hint, key2, iv))

    key1 = key2 = '{0:0>16x}'.format(idx + 1).encode()

for i in range(len(key1)):
    for j in range(len(key2_table)):
        if key1_table[i] == key2_table[j]:
            print("key1 = {}\nkey2 = {}".format(i, j))
