from pwn import *
import gmpy2
from tqdm import tqdm

context.arch = "amd64"

r = remote("mercury.picoctf.net", 61477)


flag = r.recvline().strip().decode().split(" ")[-1]
n = r.recvline().strip().decode().split(" ")[-1]
e = r.recvline().strip().decode().split(" ")[-1]

def call_oracle(plaintext):
    r.recvuntil(b"I will encrypt whatever you give me: ")
    r.sendline(plaintext.encode())
    return r.recvline().strip().decode().split(" ")[-1]

current_char = ""
output_flag = "picoCTF{bad_1d3a5"
the_last_cipher = []

for i in range(1, len(output_flag)+1):
    output = call_oracle(output_flag[:i])
    for j in the_last_cipher:
        output = output.replace(j, "")
    the_last_cipher.append(output)

while current_char != "}":
    for i in string.printable:
        output = call_oracle(output_flag + i)
        for j in the_last_cipher:
            output = output.replace(j, "")
        if output in flag:
            the_last_cipher.append(output)
            current_char = i
            output_flag += i
            print(output_flag)
            break