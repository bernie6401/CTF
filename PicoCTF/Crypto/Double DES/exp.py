from pwn import *
from tqdm import trange
import ddes
from Crypto.Cipher import DES

context.arch = 'amd64'

r = remote("mercury.picoctf.net", 37751)

r.recvline()
flag = r.recvline().strip().decode()
log.info("Encrypted Flag is: {}".format(flag))

message = ddes.pad('1234')
r.recvuntil(b"What data would you like to encrypt? ")
r.sendline(message)
enc_message = r.recvline().strip().decode()

log.info("Encrypted Message is: {}".format(enc_message))

r.close()


for i in trange(999999):
    key1 = ddes.pad("".join("{:0>6d}".format(i)))
    for j in trange(999999):
        key2 = ddes.pad("".join("{:0>6d}".format(j)))
        cipher1 = DES.new(key1, DES.MODE_ECB)
        enc_msg1 = cipher1.encrypt(message)
        cipher2 = DES.new(key2, DES.MODE_ECB)
        enc_msg2 = cipher2.decrypt(binascii.unhexlify(enc_message))

        if enc_msg2 == enc_msg1:
            print(key1, key2)
            print("flag = ", cipher1.decrypt(cipher2.decrypt(binascii.unhexlify(flag))))

