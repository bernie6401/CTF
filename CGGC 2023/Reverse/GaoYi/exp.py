from pwn import *

r = process('./gaoyi')

print(r.recvlines(26))
key = ["H0", "S2", "C8", "S5", "S7", "SA", "H2", "HA", ]

# raw_input()
for i in range(len(key)):
    skip = f'Card {i}'
    r.sendlineafter(skip.encode(), key[i].encode())

r.interactive()