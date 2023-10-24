f = open('./cipher.txt', 'r').read()
pt = open('./flag.txt', 'w')

flag = "\n".join([f[100 * i : 100 * i + 100] for i in range(len(f) // 100)])
pt.write(flag)