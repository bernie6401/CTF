import base64
import requests

s = requests.session()
url = 'http://mercury.picoctf.net:43275/'
s.get(url)
cookie = s.cookies['auth_name']
b64_cookie = base64.b64decode(cookie)
b64_cookie = base64.b64decode(b64_cookie).decode()
# print()
for i in range(0, 128):
    pos = i // 8
    guessdec = b64_cookie[0:pos] + chr(ord(b64_cookie[pos])^(1 << (i%8))) + b64_cookie[pos+1:]
    guessenc1 = base64.b64encode(guessdec)

    guess = base64.b64encode(base64.b64encode(guessdec))

    r = requests.get(url, cookies={"auth_name":guess})

    if "pico" in r.text:
        print(r.text)


# file = open('./output.txt', 'r')
# # b64_file = open('./base64_output.txt', 'a')
# for f in file.readlines():
#     print(type(f))
#     with open('./base64_output.txt', "a") as b64_file:
#         b64_file.write(base64.b64decode(f))

# b64_file.close()
# file.close()