from pwn import *
from hashlib import md5
import os
from string import ascii_lowercase, digits
from random import choice

r = remote('172.31.200.2', 40004)

def get_random_string(length):
    return "".join([choice(ascii_lowercase + digits) for _ in range(length)])

print(r.recvuntil(b'here is your prefix: '))
prefix = r.recvline()[:-1]
print(r.recvuntil(b'your hash result must end with: '))
ended = r.recvline()[:-1].decode()

log.info(f"{prefix=}\n{ended=}")

while True:
    ans = prefix + get_random_string(8).encode()
    user_hash = md5(ans).hexdigest()
    # print(user_hash)
    if ans[:5] == prefix and user_hash[-6:] == ended[-6:]:
        log.success("Find Collision~~~")
        r.sendlineafter(b'Enter the string that you want to hash: ', ans)
        break
print(r.recvline())
r.interactive()