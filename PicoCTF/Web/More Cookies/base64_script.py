import base64
import requests
from tqdm import trange

s = requests.session()
url = 'http://mercury.picoctf.net:43275/'
s.get(url)
cookie = s.cookies['auth_name']
b64_cookie = base64.b64decode(cookie)
b64_cookie = base64.b64decode(b64_cookie)

for i in trange (0,128):    # When i==72, we'll get the flag
    pos=i//8
    guessdec=b64_cookie[0:pos]+((b64_cookie[pos]^(1 << (i%8))).to_bytes(1,'big'))+b64_cookie[pos+1:]
    guess=base64.b64encode(base64.b64encode(guessdec)).decode()
    r=requests.get(url,cookies={"auth_name": guess})
    if "pico" in r.text:
        print(r.text)
        print(guess)