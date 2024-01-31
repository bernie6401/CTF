from random import choice, randint
from string import ascii_uppercase
from secret import FLAG

words = open("./Crypto/Encode not Encrypt/fasttrack.txt").read().splitlines()
selected = [choice(words) for _ in range(100)]
assert all(word in words for word in selected)
ans = " ".join(selected)

def a(s):
    return "".join(hex(ord(c))[2:] for c in s)

b_chars = 'zyxwvutsrqponmlkjihgfedcba'
def b(s):
    result = ""
    for c in s:
        binary = f'{ord(c):08b}'
        front, back = binary[:4], binary[4:]
        result += b_chars[int(front, 2)] + b_chars[int(back, 2)]
    return result

c_chars = '?#%='
def c(s):
    result = ""
    for c in s:
        binary = f'{ord(c):08b}'
        for i in range(0, 8, 2):
            result += c_chars[int(binary[i:i+2], 2)]
    return result

def d(s):
    return "".join(oct(ord(c))[2:] for c in s)

func = {0: a, 1: b, 2: c, 3: d}
encodeds = []
hint = ""
for word in selected:
    num = randint(0, 3)
    encodeds.append(func[num](word))
    for bit in f'{num:02b}':
        ch = choice(ascii_uppercase)
        hint += ch if bit == '1' else ch.lower()

print(selected)
print(" ".join(encodeds))
print(hint)

user_input = input("Enter the answer: ")
if user_input == ans:
    print(FLAG)
