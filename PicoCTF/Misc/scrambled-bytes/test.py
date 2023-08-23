import random
import subprocess

arrival_time = 1614044650.913789387
data = None

with open('./PicoCTF/Misc/scrambled-bytes/data', 'r') as f:
    data = f.read()
    
data = bytearray([int(d, 16) if d != '' else 0 for d in data.split('\n')])

data[434-1] = 0x23
data[1700-1] = 0x0f
# print(data)

# random.seed(int(arrival_time))
random.seed(1614044650)
shuffle_idx = [i for i in range(len(data)-1)]
print(len(shuffle_idx))
random.shuffle(shuffle_idx)
print(shuffle_idx)
decoded = bytearray([0 for i in range(len(data))])

for i in range(len(data)-1):
    port = random.randrange(65536)
    tmp = data[i]^random.randrange(256)
    decoded[shuffle_idx[i]] = tmp


with open('flag.png', 'wb') as f:
    f.write(decoded)