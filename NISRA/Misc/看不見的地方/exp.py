import zlib
import struct
import sys

filename = sys.argv[1]
with open(filename, 'rb') as f:
    all_b = f.read()
    crc32key = int(all_b[29:33].hex(),16)
    data = bytearray(all_b[12:29])
    n = 4095
    for w in range(n): 
        width = bytearray(struct.pack('>i', w))
        for h in range(n):
            height = bytearray(struct.pack('>i', h))
            for x in range(4):
                data[x+4] = width[x]
                data[x+8] = height[x]
            crc32result = zlib.crc32(data)
            if crc32result == crc32key:
                print("寬為：{}(hex), {}(int)".format(width.hex(), int(width.hex(), 16)))
                print("高為：{}(hex), {}(int)".format(height.hex(), int(height.hex(), 16)))
                exit(0)