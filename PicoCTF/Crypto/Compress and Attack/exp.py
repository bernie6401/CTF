from pwn import *

context.arch = 'amd64'

r = remote("mercury.picoctf.net", 33976)

def oracle(plaintext):
    r.recvuntil(b"Enter your text to be encrypted: ")
    r.sendline(plaintext.encode())
    nonce = r.recvline().strip().hex()
    encrypted_text = r.recvline().strip().hex()
    return r.recvline().strip().decode()


current_char = ""
guessing_flag = "picoCTF{"
fit_length = oracle(guessing_flag)
print(guessing_flag)
while current_char != "}":
    for i in string.printable:
        if oracle(guessing_flag + i) == fit_length:
            print(i)
            guessing_flag += i
            current_char = i
            break
        
print(guessing_flag)
r.close()