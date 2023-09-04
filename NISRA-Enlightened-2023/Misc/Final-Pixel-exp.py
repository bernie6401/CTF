from PIL import Image
from base64 import b64decode

img = Image.open("./NISRA-Enlightened-2023/Misc/Final-Pixel.png")

pixels = []
for row in range(8):	# 8 rows
	for col in range(8):	# 8 columns
		r, g, b = img.getpixel((row * 64 + 1, col * 64 + 1))	# each grid: 64 x 64
		if r == 255 and g == 255 and b == 255:
			break
		else:
			pixels.append((chr(r), chr(g), chr(b)))
	if r == 255 and g == 255 and b == 255:
		break

flag = ""
print(pixels)
for r, g, b in pixels:
	flag += r + g + b
print(flag)
print(b64decode(flag.encode()))