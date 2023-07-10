from pwn import *

context.arch = 'amd64'

r = remote('127.0.0.1', 6401)

r.interactive()