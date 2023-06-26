import base64
import gmpy2
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import urlsafe_b64encode, urlsafe_b64decode
import jwt
from Crypto.PublicKey import RSA
from tqdm import trange

'''
Compute RSA Public Key - (N, e)
'''
def initialize(message, c_or_m):
    if c_or_m == 'c':
        return gmpy2.mpz(int(base64.urlsafe_b64decode(message).hex(), 16))
    elif c_or_m == 'm':
        return gmpy2.mpz(int(pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(SHA256.new(message.encode()), 256).hex(), 16))

ciphertext = {
    0 : "YrTx9te5xI8f7GacKks7qwhaRDLm2oW-uGc9aPxwttU==",
    1 : "4opwTohD6avUxpp59YyZxUsh3aRvs1Ut8S-vJfERGSk==",
    2 : "8WBt-8JOfqkuzlILqEz_aY2_7J3anRnAXTVRU2-7mKA==",
    3 : "6mYo4u8BFqjUQqhR-btYg51VGeFCRkFiR6iR78Y21DA=="
}

plaintext = {
    0 : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoxNjg3NzYzMjY0NjQzLCJhZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwOS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzExNC4wIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3NjMyNjV9",
    1 : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoxNjg3NzYzNDM0MzQwLCJhZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwOS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzExNC4wIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3NjM0MzR9",
    2 : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoxNjg3NzYzNDcxNDMwLCJhZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwOS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzExNC4wIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3NjM0NzF9",
    3 : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdXRoIjoxNjg3NzYzNDg1MDc1LCJhZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEwOS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzExNC4wIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2ODc3NjM0ODV9"
}

c = {}
m = {}
for i in range(4):
    c[i] = initialize(ciphertext[i], 'c')
    m[i] = initialize(plaintext[i], 'm')

e = gmpy2.mpz(65337) # The default parameter in openssl
for i in trange(10000):
    e -= 2
    a_N = c[0]**e - m[0]
    b_N = c[1]**e - m[1]
    c_N = c[2]**e - m[2]

    n = gmpy2.gcd(a_N, b_N, c_N)#
    if n != 1:
        print("i = {}, n = {}".format(i, n))


'''
Generate PEM File about RSA Public Key
'''
# n = 0x8ffcd5ae700b26f96316817101f254071b082b209196371eabf52d9a5e80eb64d5f4c4a1533e147f3c27b7e941622c25db41f21f502f6fd94d4b994b9448d824f24d27845da8cf5f8e10ddd1ac05ef54c490aaa7ac028efafe205d0633c62cd72ff3f874497a67c5458adaec91be0859e82a300f345ecd007115b9cb653e6b9ba670ea61e31b4b4b13bcba8cb324777e751c6b9fe531f5c6d61dd459674e57d08c03e1202f66b835220d097a9429fa5dcc22f8fbf80ddb1bb0b59ad98d4b462619ec3642ea1f6fdb7420b9602b4a8c4f66aaa0932b36d7ab4102392cd71803076acf2947cd253ea5580a0c1228ddd7647ef3d6e7c43f3d5d9654cf0d47d390d1
# e = 0x10001
# key_params = (n, e)
# key = RSA.construct(key_params)
# f = open('./rsa-public-key.pem', 'w')
# f.write(key.exportKey().decode())
# f.close()




'''
Create Signature
'''
# import jwt
# import hashlib
# import hmac
# key = b"-----BEGIN PUBLIC KEY-----\n\
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj/zVrnALJvljFoFxAfJU\n\
# BxsIKyCRljceq/Utml6A62TV9MShUz4Ufzwnt+lBYiwl20HyH1Avb9lNS5lLlEjY\n\
# JPJNJ4RdqM9fjhDd0awF71TEkKqnrAKO+v4gXQYzxizXL/P4dEl6Z8VFitrskb4I\n\
# WegqMA80Xs0AcRW5y2U+a5umcOph4xtLSxO8uoyzJHd+dRxrn+Ux9cbWHdRZZ05X\n\
# 0IwD4SAvZrg1Ig0JepQp+l3MIvj7+A3bG7C1mtmNS0YmGew2Quofb9t0ILlgK0qM\n\
# T2aqoJMrNterQQI5LNcYAwdqzylHzSU+pVgKDBIo3ddkfvPW58Q/PV2WVM8NR9OQ\n\
# 0QIDAQAB\n\
# -----END PUBLIC KEY-----\n"
# header = '{"alg": "HS256", "typ": "JWT"}'
# payload = '{"username":"admin","flag1":"CNS{JW7_15_N07_a_900d_PLACE_70_H1DE_5ecrE75}","exp":1786583759}'
# header = base64.urlsafe_b64encode(bytes(header, "utf-8")).decode().replace("=", "").encode()
# payload = base64.urlsafe_b64encode(bytes(payload, "utf-8")).decode().replace("=", "").encode()
# sig = hmac.new(key, header + b'.' + payload, hashlib.sha256).digest().strip()
# sig = base64.urlsafe_b64encode(sig).decode().replace("=", "")
# jwt = '{}.{}.{}'.format(header.decode(), payload.decode(), sig)
# print(jwt)