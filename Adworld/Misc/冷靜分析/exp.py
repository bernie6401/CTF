from base64 import b64decode
import zipfile

f = open('./basezip.txt', 'r').read().split(',')[-1]
f1 = open('./cipher.zip', 'wb')
f1.write(b64decode(f))
print(bytes.fromhex(b64decode(f).hex()).decode('cp437'))
f1.close()
f.close()