from Crypto.Cipher import AES
import base64


IV = b'QWERTYUIOPASDFGH'
str1 = '19aaFYsQQKr+hVX6hl2smAUQ5a767TsULEUebWSajEo='


def decrypt(encrypted):
  aes = AES.new(IV, AES.MODE_CBC, IV)
  return aes.decrypt(encrypted)


def encrypt(message):
  length = 16
  count = len(message)
  padding = length - (count % length)
  message = message + '\0' * padding
  aes = AES.new(IV, AES.MODE_CBC, IV)
  return aes.encrypt(message)


str = 'this is a test'
example = decrypt(base64.b64decode(str1))
print(example)