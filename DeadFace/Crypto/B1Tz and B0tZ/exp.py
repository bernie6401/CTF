from string import digits
root = './DeadFace/Crypto/B1Tz and B0tZ/'
f = open(root + '4efdxrub.txt', 'r').read().split(' ')

pt = ""
ct = ""
flag = []
for i, byte in enumerate(f):
    tmp = hex(int(byte, 2))[2:]
    if len(tmp) < 2:
        tmp = '0' + tmp
    if i > 143:
        flag.append(tmp)
    else:
        pt += tmp
print(f"pt = {bytes.fromhex(pt).decode('utf-8')}")
print(f'ct = {"".join([bytes.fromhex(i).decode("utf-8") for i in flag])}')
flag = "".join([bytes.fromhex(i).decode("utf-8") for i in flag]).rstrip('\n').lstrip('\n').split(' ')
print(f'ROT flag = {"".join([bytes.fromhex(i).decode("utf-8") for i in flag])}')