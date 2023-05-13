from pwn import *

r = remote("chals1.ais3.org", 1001)
context.arch = 'amd64'



r.interactive()