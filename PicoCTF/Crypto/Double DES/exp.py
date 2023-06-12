from pwn import *
from tqdm import tqdm
import ddes
from Crypto.Cipher import DES
from itertools import product

context.arch = 'amd64'

# r = remote("mercury.picoctf.net", 37751)

# r.recvline()
# flag = r.recvline().strip().decode()
# log.info("Encrypted Flag is: {}".format(flag))

# message = ddes.pad('00')
# r.recvuntil(b"What data would you like to encrypt? ")
# r.sendline(message)
# enc_message = r.recvline().strip().decode()

# log.info("Encrypted Message is: {}".format(enc_message))

# r.close()
message = ddes.pad(binascii.unhexlify('00').decode())
enc_message = bytes.fromhex("6ee2234a9e61e816")
flag = bytes.fromhex("0446d14e0b7dbd6202a704e86d05747382cc26567449bbebb3ab76f42ce8be4957c2731923859baf")


my_dict = {}
for i in tqdm(product(string.digits, repeat=6), total=10 ** 6):
    key1 = ddes.pad("".join(i))
    cipher1 = DES.new(key1, DES.MODE_ECB)
    enc_msg1 = cipher1.encrypt(message)
    my_dict[enc_msg1] = key1

for j in tqdm(product(string.digits, repeat=6), total=10 ** 6):
    key2 = ddes.pad("".join(j))
    cipher2 = DES.new(key2, DES.MODE_ECB)
    dec_msg2 = cipher2.decrypt(enc_message)
    if dec_msg2 in my_dict:
        cipher1 = DES.new(my_dict[dec_msg2], DES.MODE_ECB)
        print("flag = ", bytes.fromhex(cipher1.decrypt(cipher2.decrypt(flag)).hex()).decode('cp437'))

