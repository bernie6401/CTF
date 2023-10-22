import string

# def test():
#     pekoS = ['pekO', 'PEko', 'PekO', 'pEKo', 'PEKO', 'peko', 'PEKo', 'peKo', 
#             'peKO', 'Peko', 'PeKo', 'pEkO', 'pEKO', 'pEko', 'PEkO', 'PeKO']


#     with open('message2.txt', encoding='utf8') as f, open('message2.peko', 'w') as o:
#         peko = ''
#         for c in f.read().lower():
#             if (c in string.ascii_letters):
#                 # 'a' --> 61
#                 for x in c.encode().hex():
#                     peko += pekoS[int(x, 16)]
#             else:
#                 peko += c
#         o.write(peko)


#     with open('flag2.txt', encoding='utf8') as f, open('flag2.peko', 'w') as o:
#         flag = f.read()
#         # assert len(flag) == 62
#         peko = ''
#         for p in flag:
#             # a --> 0061
#             print(f"{ord(p):04x}")
#             for i in f"{ord(p):04x}":
#                 peko += pekoS[int(i, 16)]
#         o.write(peko)

def find(s:str, arr:list):
    for i, a in enumerate(arr):
        if(a == s):
            return i
    return None

def get_flag(pekoS):
    ans = ""
    with open('./神盾獎/Crypto/peko/flag.peko', encoding='utf-8') as f:
        peko_file = f.read()
        for p in range(0, len(peko_file), 16):
            this_p = peko_file[p:p+16]
            
            char_hex = 0
            for i in range(0, len(this_p), 4):
                char = this_p[i:i+4]
                index = find(char, pekoS)
                char_hex += index * int(pow(16, 3-i//4))

            ans += chr(char_hex)
    return ans

def get_msg(pekoS):
    ans = ""
    with open("message.peko", encoding='utf-8') as f:
        msg_peko = f.read()
        i = 0
        while(i < len(msg_peko)):
            if(msg_peko[i]=='p' or msg_peko[i]=='P'):
                chr_hex = 0
                for j in range(2):
                    this_peko = msg_peko[i:i+4]
                    index = find(this_peko, pekoS)
                    chr_hex += index * pow(16, 1-j)
                    i += 4
                ans += chr(chr_hex)
            else:
                ans += msg_peko[i]
                i += 1
    return ans

if __name__ =='__main__':
    # test()
    # print()
    # PEKOPEko: 65(e)
    # PEKOPEkO: 61(a)
    # PEKOPeko: 6f(o)
    # PEKOpeko: 69(i)
    # PekOpEKO: 74(t)
    # PEKOpEko: 6e(n)
    # PekOpEKo: 73(s)
    # PekOPeKo: 72(r)
    # PEKOpeKO: 68(h)
    # PEKOpeKo: 6c(l)
    # k: 6b --> m: 6d
    # n: 6e --> o: 6f
    pekoS = ['pekO', 'PEko', 'PekO', 'pEKo', 
             'PEKO', 'peko', 
             'PEKo', 'peKo', # a: 61~7a
            'peKO', 'Peko', 'PeKo', 'pEkO', 'pEKO', 'pEko', 'PEkO', 'PeKO']
    
    new_pekos = [''] * 16
    
    new_pekos[0x1] = "PEkO"
    new_pekos[0x2] = "PeKo"
    new_pekos[0x3] = "pEKo"
    new_pekos[0x4] = "pEKO"
    new_pekos[0x5] = "PEko"
    new_pekos[0x6] = "PEKO"
    new_pekos[0x7] = "PekO"
    new_pekos[0x8] = "peKO"
    new_pekos[0x9] = "peko"
    new_pekos[0xb] = "PeKO"
    new_pekos[0xc] = "peKo"
    new_pekos[0xd] = "pEkO"
    new_pekos[0xe] = "Peko"
    new_pekos[0xf] = "pEko"

    j = 0
    for i in range(16):
        if(new_pekos[i] == ''):
            while(j < 16):
                if(pekoS[j] not in new_pekos):
                    new_pekos[i] = pekoS[j]
                    j += 1
                    break
                j += 1

    ans = get_flag(new_pekos)
    print(ans)
    