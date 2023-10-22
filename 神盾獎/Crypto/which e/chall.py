from SECRET import flag, es
from Crypto.Util.number import *
import random

p = getPrime(1024)
q = getPrime(1024)
n = p*q
e1, e2 = random.choices(es, k=2)
ct1, ct2 = pow(bytes_to_long(flag), e1, n), pow(bytes_to_long(flag), e2, n)

print(f'{n   = }')
print(f'{es  = }')
print(f'{ct1 = }')
print(f'{ct2 = }')
