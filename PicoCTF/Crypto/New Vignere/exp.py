import string
from itertools import product, zip_longest

LOWERCASE_OFFSET = ord("a")
ALPHABET =  string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def b16_decode(enc):
	plain = ""
	for i in range(0, len(enc), 2):
		b1 = "{0:04b}".format(ALPHABET.index(enc[i]))
		b2 = "{0:04b}".format(ALPHABET.index(enc[i+1]))
		binary = int(b1+b2, 2)
		plain += chr(binary)
	return plain

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

def unshift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]

def decrypt(enc, key):
	plain = ''
	for i, c in enumerate(enc):
		plain += unshift(c, key[i%len(key)])
	return plain

ciphertext = 'bgjpchahecjlodcdbobhjlfadpbhgmbeccbdefmacidbbpgioecobpbkjncfafbe'
good = set(b16_encode(string.hexdigits[:16]))

for keylen in range(2, 15):
	encs = [ciphertext[i::keylen] for i in range(keylen)]
	print("keylen: " + str(keylen))
	print(encs)
	plains = []
	for i, enc in enumerate(encs):
		plains.append([])
		for key in ALPHABET:
			plain = decrypt(enc, key)
			if all(c in good for c in plain):
				plains[i].append(plain)
	if any(len(p) == 0 for p in plains):
		continue
	print(plains)

	first = True
	for prod in product(*plains):
		plaintext = ""
		for zipped in zip_longest(*prod):
			plaintext += "".join(filter(None, zipped))
		if (first):
			print(plaintext)
			first = False
		dec = b16_decode(plaintext)
		if all(c in string.hexdigits[:16] for c in dec):
			print(dec)
			print(plaintext)