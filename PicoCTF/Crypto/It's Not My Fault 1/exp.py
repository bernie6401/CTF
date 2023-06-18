from pwn import *
from tqdm import trange
import hashlib

context.arch = 'amd64'

r = remote('mercury.picoctf.net', 41175)

r.recvuntil(b'Enter a string that starts with "')
tmp = r.recvline().strip().decode()

value1 = tmp.split('"')[0]
value2 = tmp.split(": ")[-1]

log.info("Prefix = {}, Postfix = {}".format(value1, value2))
for i in trange(20000000000):
    guess_collision = hashlib.md5((value1 + str(i)).encode()).hexdigest()
    if guess_collision[-6:] == value2:
        r.sendline((value1 + str(i)).encode())
        print("Collision Found: {}".format(value1 + str(i)))
        break

n = r.recvline().strip().decode().split(" ")[-1]
print("n = {}".format(n))


r.interactive()