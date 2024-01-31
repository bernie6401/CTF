import string

flags = open('./flags.txt', 'r').read().splitlines()
candidate_file = open('candidate.txt', 'w')
sha1_flag = "8d41c13d201aa912146145ceff9589ed194c97a7"

enc_flag = "TSC{PU[RkUR\tn^PE<RY\rX9=⸮\0D<@n\f}"


flag = "TSC{"
for candidate_flag in flags:
    for j in range(7, len(enc_flag)):
        tmp = chr(ord(candidate_flag[j % 40]) ^ ord(enc_flag[j - 3]) ^ 1)
        if tmp not in string.printable:
            break
        else:
            flag += tmp
    if tmp not in string.printable:
        flag += '\n'
        pass
    else:
        flag += '}\nTSC{'
candidate_file.write(flag)