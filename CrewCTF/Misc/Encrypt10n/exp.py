from pwn import *
from tqdm import trange

f = open("./dump.raw", "rb").read()
new_png_count = 0

file_sig_png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
file_sig_png_end = [0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]
count_header = 0
count_end = 0
writable = False

for i in trange(91400120, 114091167):
    if file_sig_png_header[count_header] == f[i] and not writable:
        if count_header == len(file_sig_png_header)-1:
            new_png = open("./new_png_" + str(new_png_count) + ".png", "wb")
            new_png.write(f[i-7:i+1])
            # new_png.write(f[i-7:i+(114091156 - 91400120)])
            # new_png.close()
            writable = True
            count_header = 0
        else:
            count_header += 1
    elif writable:
        if file_sig_png_end[count_end] == f[i]:
            if count_end == len(file_sig_png_end)-1:
                new_png.write(bytes([f[i]]))
                new_png.close()
                new_png_count += 1
                writable = False
            else:
                count_end += 1
                new_png.write(bytes([f[i]]))
        else:
            new_png.write(bytes([f[i]]))
            count_end = 0
    else:
        count_header = 0
        count_end = 0