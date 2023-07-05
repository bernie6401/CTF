enc_flag = [74, 83, 71, 93, 65, 69, 3, 84, 93, 2, 90, 10, 83, 87, 69, 13, 5, 0, 93, 85, 84, 16, 1, 14, 65, 85, 87, 75, 69, 80, 70, 1]
key = [0x38, 0x36, 0x31, 0x38, 0x33, 0x36, 0x66, 0x31, 0x33, 0x65, 0x33, 0x64, 0x36, 0x32, 0x37, 0x64, 0x66, 0x61, 0x33, 0x37, 0x35, 0x62, 0x64, 0x62, 0x38, 0x33, 0x38, 0x39, 0x32, 0x31, 0x34, 0x65]

FLAG = []
for a, b in zip(enc_flag, key):
    FLAG.append(bytes.fromhex(hex(a ^ b)[2:]).decode('utf-8'))

print("".join(FLAG))