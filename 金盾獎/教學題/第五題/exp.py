from pwn import *

r = process('./Bomb.exe')
r.recvuntil(b'P1ease count A(')
A = r.recvuntil(b')')[:-1].decode()
sign = r.recv(3).decode()
B = r.recvline()[2:-2].decode()

log.info(f'A({A}) {sign} B({B}) = {eval(A + sign + B)}')
r.sendlineafter(b'Enter your answer: ', str(eval(A + sign + B)).encode())

r.interactive()