from pwn import *
from string import ascii_letters, digits
import json
from tqdm import trange


def gen_plaintext(length):
    return ''.join(random.choice(ascii_letters + digits) for _ in range(length))


root = "./PicoCTF/Crypto/PowerAnalysis- Part 1/"
pt = [gen_plaintext(16) for _ in range(50)]
print(pt)
json_file = [None] * len(pt)

for i in trange(len(pt)):
    r = remote('saturn.picoctf.net', 61056)
    r.sendlineafter(b'hex: ', pt[i].encode('utf-8').hex().encode())
    r.recvuntil(b'power measurement result:  ')
    pm = r.recvline().decode().strip()
    json_file[i] = {}
    json_file[i]["pt"] = [ord(digit) for digit in pt[i]]
    json_file[i]["pm"] = pm

    r.close()

json_object = json.dumps(json_file)
with open(root + "tmp.json", 'w') as outfile:
    outfile.write(json_object)

f = open(root + "tmp.json", "r").read()
new_f = open(root + "traces.json", "w")
new_content = f.replace('"[', "[").replace(']"', "]")
new_f.write(new_content)
new_f.close()