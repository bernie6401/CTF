import string

candidate = string.ascii_lowercase + string.digits + "_ "
def check_characters(string):
    for char in string:
        if char not in candidate:
            return False
    return True

f = open("./result.txt", "rb").read().splitlines()#D:/Download/Trash

for i in range(len(f)):
    try:
        tmp = f[i].decode()
        if check_characters(tmp):
            print(f[i].decode())
    except:
        pass