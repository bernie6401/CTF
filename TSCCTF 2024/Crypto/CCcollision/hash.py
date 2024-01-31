from hashlib import md5
from string import ascii_lowercase, digits
from random import choice
from secret import FLAG

def get_random_string(length):
    return "".join([choice(ascii_lowercase + digits) for _ in range(length)])

prefix = get_random_string(5)
hashed = md5(get_random_string(30).encode()).hexdigest()

print("here is your prefix: " + prefix)
print("your hash result must end with: " + hashed[-6:])

user_input = input("Enter the string that you want to hash: ")
user_hash = md5(user_input.encode()).hexdigest()

if user_input[:5] == prefix and user_hash[-6:] == hashed[-6:]:
    print(FLAG)