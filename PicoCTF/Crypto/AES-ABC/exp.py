#!/usr/bin/env python

from Crypto.Cipher import AES
# from key import KEY
import os
import math

BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))


def to_bytes(n):
    s = hex(n)
    s_n = s[2:]
    if 'L' in s_n:
        s_n = s_n.replace('L', '')
    if len(s_n) % 2 != 0:
        s_n = '0' + s_n
    decoded = bytes.fromhex(s_n)#s_n.decode('hex')

    pad = (len(decoded) % BLOCK_SIZE)
    if pad != 0: 
        decoded = b"\0" * (BLOCK_SIZE - pad) + decoded
    return decoded


def remove_line(s):
    # returns the header line, and the rest of the file
    return s[:s.index(b'\n') + 1], s[s.index(b'\n')+1:]


def parse_header_ppm(f):
    data = f.read()

    header = b""

    for i in range(3):
        header_i, data = remove_line(data)
        header += header_i

    return header, data
        

def pad(pt):
    padding = BLOCK_SIZE - len(pt) % BLOCK_SIZE
    return pt + (chr(padding) * padding)


def abc_decrypt(ct):
    blocks = [ct[i * BLOCK_SIZE:(i+1) * BLOCK_SIZE] for i in range(len(ct) // BLOCK_SIZE)]

    k = 0
    for idx in range(len(blocks)-1, 0, -1):
        curr_blk = int(blocks[idx].hex(), 16)
        prev_blk = int(blocks[idx-1].hex(), 16)
        if (k * UMAX + curr_blk - prev_blk) < 0:
            tmp = UMAX + curr_blk - prev_blk
        else:
            tmp = curr_blk - prev_blk

        blocks[idx] = to_bytes(tmp)

    pt_abc = b"".join(blocks)
    return pt_abc

if __name__=="__main__":
    with open('body.enc.ppm', 'rb') as f:
        header, data = parse_header_ppm(f)

    pt_img = abc_decrypt(data)
    
    # iv, c_img, ct = aes_abc_encrypt(data)

    with open('body.dec.ppm', 'wb') as fw:
        fw.write(header)
        fw.write(pt_img)
