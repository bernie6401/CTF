enc_flag = open("./rev_this", "r").read()

FLAG = "picoCTF{"
for i in range(8, len(enc_flag)):
    enc_flag[i]
    if i % 2 == 0:
        FLAG += chr(ord(enc_flag[i])-5)
    else:
        FLAG += chr(ord(enc_flag[i])+2)

print(FLAG+"}")