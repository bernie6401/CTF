from base64 import b64decode

f = open('./Crypto/Lab 0x00 - secret.txt', 'r').read()
flag = open('./Crypto/Lab 0x00 - solved.png', 'wb')
print(b64decode(f.encode()))
flag.write(b64decode(f.encode()))
flag.close()