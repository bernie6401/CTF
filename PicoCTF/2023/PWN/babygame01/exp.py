from pwn import *

r = remote("saturn.picoctf.net", 60350)

r.recvuntil(b'X\n')

# r.sendline(b'd')

r.interactive()