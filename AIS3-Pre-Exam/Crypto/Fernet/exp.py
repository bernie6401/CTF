import os
import base64
from cryptography.fernet import Fernet
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from pwn import *

def decrypt(ciphertext, password, salt):
    key = PBKDF2(password.encode(), salt, 32, count=1000, hmac_hash_module=SHA256)  
    f = Fernet(base64.urlsafe_b64encode(key))  
    plaintext = f.decrypt(ciphertext)  
    return plaintext

leak_password = 'mysecretpassword'
ciphertext = 'iAkZMT9sfXIjD3yIpw0ldGdBQUFBQUJrVzAwb0pUTUdFbzJYeU0tTGQ4OUUzQXZhaU9HMmlOaC1PcnFqRUIzX0xtZXg0MTh1TXFNYjBLXzVBOVA3a0FaenZqOU1sNGhBcHR3Z21RTTdmN1dQUkcxZ1JaOGZLQ0E0WmVMSjZQTXN3Z252VWRtdXlaVW1fZ0pzV0xsaUM5VjR1ZHdj'
tmp = base64.b64decode(ciphertext)
salt = tmp[:16]
ciphertext = tmp[16:]
print(decrypt(ciphertext, leak_password, salt))