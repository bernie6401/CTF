from base64 import b64decode as b

s = "eux_Z]\\ayiqlog`s^hvnmwr[cpftbkjd"
s2 = "Zf91XhR7fa=ZVH2H=QlbvdHJx5omN2xc"

s = s.encode('utf-8')
s2 = s2.encode('utf-8')

FLAG = ""

for i in range(len(s2)):
    FLAG += bytes.fromhex('{:x}'.format(s2[s[i] - 90])).decode('utf-8')

print(b(FLAG).decode())