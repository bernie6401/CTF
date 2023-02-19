import requests

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36', 
            'Host':'mercury.picoctf.net:64944',
            'Accept-Encoding':'gzip, deflate',
            'Accept-Language':'zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7'}
url = 'http://mercury.picoctf.net:64944/'
cookies = dict(name='-1')
r = requests.get(url, headers=headers, cookies=cookies)
# r = requests.post('http://mercury.picoctf.net:64944/', data = {'name' : '-1'})

print(r.text) #列出文字
print(r.encoding) #列出編碼
print(r.status_code) #列出 HTTP 狀態碼
print(r.headers) #列出 HTTP Response Headers
print(r.cookies)
# print(r.headers['Content-Type']) #印出 Header 中的 Content-Type