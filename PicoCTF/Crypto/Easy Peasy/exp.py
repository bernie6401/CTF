from pwn import *
import sys


r = remote('mercury.picoctf.net', 11188)
context.arch = 'amd64'
r.recvline()
r.recvline()
cipher_flag = r.recvlineS(keepends = False)
log.info(f"Cipher flag: {cipher_flag}")

r.recvline()
r.sendline(b'a'*(50000 - int(len(cipher_flag) / 2)))
r.recvline()
r.recvline()
r.recvline()
r.sendline(b'a' * 32)
r.recvline()
encrypt_32a = r.recvlineS(keepends = False)
log.info(f"Cipher 'a' * 32: {encrypt_32a}")

plaintext_32a = '61' * 32
log.info(f"Plaintext 'a' * 32: {plaintext_32a}")

r.interactive()