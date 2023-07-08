f = open("./password.txt", 'r').read().splitlines()
passwd_dic = {}
for i in f:
    if i not in passwd_dic:
        passwd_dic[i] = 0
    else:
        passwd_dic[i] += 1

print(passwd_dic)