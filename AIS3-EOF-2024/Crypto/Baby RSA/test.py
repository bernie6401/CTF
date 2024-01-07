from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
import random
import binascii
from secret import FLAG
import math

e = 3
BITSIZE =  1024
key = RSA.generate(BITSIZE)
n = key.n
flag = bytes_to_long(FLAG)
m = math.floor(BITSIZE/(e*e)) - 100
assert (m < BITSIZE - len(bin(flag)[2:]))
r1 = random.randint(1, pow(2,m))
r2 = random.randint(r1, pow(2,m))
msg1 = pow(2,m)*flag + r1
msg2 = pow(2,m)*flag + r2

C1 = int(pow(msg1,e,n))
C2 = int(pow(msg2,e,n))
print(f'{n = }\n{C1 = }\n{C2 = }')