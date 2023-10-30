from PIL import Image
from base64 import b64decode

img = Image.open("./DeadFace/Crypto/0ff Again On Aga1n/chall.png")

pixels = []
for col in range(8):	# 8 rows
	for row in range(8):	# 8 columns
		r, g, b, _ = img.getpixel((row * 80 + 1, col * 76 + 1))	# each grid: 64 x 64
		pixels.append((chr(r), chr(g), chr(b)))

flag = ""
print(pixels)
# for r, g, b in pixels:
# 	flag += r + g + b
# print(flag)
# print(b64decode(flag.encode()))