from pwn import *

context.arch = 'amd64'
r = remote("chals1.ais3.org", 12348)

r.recvline()
r.recvline()

for i in range(30):
    question = r.recvline().decode().strip()
    ans = eval(question)
    sleep(1)
    r.sendline(str(ans).encode())

print(r.recvline())
r.interactive()