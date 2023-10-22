import random
import string
import itertools

pekoS = []

for peko in itertools.product(['P', 'p'], ['E', 'e'], ['K', 'k'], ['O', 'o']):
    pekoS.append(''.join(peko))
random.shuffle(pekoS)

# with open('message.txt', encoding='utf8') as f, open('message.peko', 'w') as o:
#     peko = ''
#     for c in f.read().lower():
#         if (c in string.ascii_letters):
#             for x in c.encode().hex():
#                 peko += pekoS[int(x, 16)]
#         else:
#             peko += c
#     o.write(peko)

root = './神盾獎/Crypto/peko/'
with open(root + 'flag.txt', encoding='utf8') as f, open(root + 'flag_test.peko', 'w') as o:
    flag = f.read()
    assert len(flag) == 62
    peko = ''
    for p in flag:
        for i in f"{ord(p):04x}":
            peko += pekoS[int(i, 16)]
    o.write(peko)
