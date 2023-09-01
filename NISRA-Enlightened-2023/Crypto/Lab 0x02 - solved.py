cipher = "TAFSLHDMKGEIYAURSSIIOFTSDAUEAEDLRWYALIIOHOELUE"
cipher = "ASRUEAEPNHFRSMTISLREITEOETYEOCLD"
for i in range(len(cipher)):
    if i == 5:
        break
    print(cipher[i:len(cipher):5], end="")