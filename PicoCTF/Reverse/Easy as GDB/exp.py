cipher = bytes.fromhex("2E6E40681D53657C175816436D5862366F436230016347333F6314636d7a00")

flag = []
for i in range(len(cipher)):
    flag.append(hex(cipher[i])[2:])


for i in range(0xABCF00D, 0xdea62e4b, 0x1FAB4D):
    tmp_idx = hex(i)[2:].encode()
    if len(tmp_idx) < 8:
        tmp_idx = b'0' + tmp_idx
    key = [int(tmp_idx[-8:-6], 16), int(tmp_idx[-6:-4], 16), int(tmp_idx[-4:-2], 16), int(tmp_idx[-2:], 16)]

    for j in range(len(cipher)):
        tmp = hex(int(flag[j], 16) ^ key[j % 4])[2:]
        flag[j] = tmp
        # cipher[j] = bytes.fromhex(hex(cipher[j] ^ key[j % 4])[2:])
print(bytes.fromhex("".join(flag)).decode('cp437'))