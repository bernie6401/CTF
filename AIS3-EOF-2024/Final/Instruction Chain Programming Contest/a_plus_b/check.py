from pwn import *

context.arch = 'amd64'

payload = asm('''
    addi rax, rbx, 30
''')
'''

    mov rbx, rdi
    add rbx, rsi
    mov rax, rbx
    ret
'''
print(payload)
banned_bytes = [0xc3, 0x48, 0x55, 0xff]

# 將 payload 轉換為 byte array
# payload_bytes = bytearray(payload, 'utf-8')

# 檢查每個字節是否在 banned_bytes 中
if any(byte in banned_bytes for byte in list(payload)):
    print('Payload contains banned bytes')
else:
    print('Payload is clean')