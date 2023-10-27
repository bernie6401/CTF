from secret import FLAG
from random import randint

p = 307163712384204009961137975465657319439
g = 1337


def encrypt(m):
    bits = bin(m)[2:]
    encrypted = []

    for b in bits:
        r = (randint(2, p) << 1) + int(b)   # 變成兩倍後和b相加
        encrypted.append(pow(g, r, p))

    return encrypted


def main():
    flag = int.from_bytes(FLAG, 'big')
    encrypted_flag = encrypt(flag)

    with open('output_test.txt', 'w') as f:
        f.write(str(encrypted_flag))


if __name__ == '__main__':
    main()
