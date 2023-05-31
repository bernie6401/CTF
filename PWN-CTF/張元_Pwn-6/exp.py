from pwn import *
r = process("./pwntools")
r = remote("120.114.62.210", 2116)

context.arch = 'amd64'

secret_num = 0x79487FF
r.sendline(p64(secret_num))
print(r.recvline())
print(r.recvline())

# print(r.recvline())
# raw_input()
for i in range(1000):
    question = str(r.recvuntil(b' = ?')).split("=")[0].split("'")[-1]
    print(question)
    ans = str(eval(question)).encode()
    print(ans)
    r.sendline(ans)

r.interactive()