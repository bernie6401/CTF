from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import binascii


context.arch = 'amd64'
r = remote("mercury.picoctf.net", 10333)

for i in range(4):
    r.recvline()

n = int(str(r.recvline().strip().decode()).split(" ")[-1])
e = int(str(r.recvline().strip().decode()).split(" ")[-1])
c = int(str(r.recvline().strip().decode()).split(" ")[-1])

log.info(f"n = {n}\ne = {e}\nc = {c}")

m = b'2'
# r.sendline(long_to_bytes(pow(bytes_to_long(m), e, n)))
r.recvuntil(b"Give me ciphertext to decrypt: ")
r.sendline(str(pow(2, e, n) * c).encode())
response = int(str(r.recvline().strip().decode()).split(" ")[-1])
plaintext = response // 2
print(binascii.unhexlify("{:x}".format(plaintext)))

r.close()