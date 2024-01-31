from pwn import *
import string

r = remote('172.31.200.2', 42816)

encoded = r.recvline()[:-1].decode().split(' ')
hint = r.recvline()[:-1].decode()
# encoded = "vysusvsutmtlwxwzwyws #%#?#%?##=#?#%?##%?%#%?##=?=#%## #=?=#=??#=?%#%%##%=%#%#=?=?%?=???=?#?=?= ?=?#?=?#?=?#?=?#?=?#?=?# #=?=#%?##=?=#%?# swtusxsttusx tntusvtmtutqtl 146151162145 70617373 tytvtmtqtltqswsvtysvtksx 141144155151156163 77696e74657232303132 swtutwsxtusv 6d6f6e6b6579 70726976617465 163145162166145162 12316515515514516262606165 ustutntwtktmtuwywxww swsutmtmtusxwxwzwzwr ustqtlsvtusxwxwzwywu swtutwsusxtqsvsq swtltkss 57656c636f6d6531323132 swsutmtmtusxwxwzwzwr #=?=#%###%?=#=?%#%###=#??%?# 163161154 uzvzwuwusswzsxtvxy 146151162145 61646d696e61646d696e ##??#????=##?=###=#=?=??#=?%#%#??%?# 53756d6d657232303131 74657374 #=#?#%###=?=#=#??%=##=?=#=?##%=??=?= 7374617277617273 73716c70617373 ##?=#=###%=##%=##%###=?%?=?%?=???=?#?=?= 61646d696e69737461746f72 #%#=#%==#%?##=#? #%#?#=?%#%?##%#=#%==#%=% swsutmtmtusxwxwzwywz tysusvsutmtlwxwzwywu ###=#%%##%=%#=#?#%###=?%?=?%?=???=?#?=#% sutltotltksstl 163157155145144141171 155157156153145171 #%?=#%==#%=##=??#%?##%=%#=%#?=?#?%?# #=?##=#=#%###=?%#=#?#=%# 313233343536 syty 6561727468 svtuswsvxmswsytnww twtrtytltstu 163145143162145164616263 #=?=#=###%=##%=##%###=?%?=?%?=???=?#?=?= 6e6574776f726b73 504073737730726421 141144155151156163 123161154163145162166145162 #=?=#=###%=##%=##%###=?%?=?%?=???=?#?=## uzvzswswsswzsxtvxy 144162141147157156 uwsutmtmtusxwxwzwyws 6d6f6e6b6579 ##??#???#=?=#=?=#=#=#%==#=?%#%#??%?# 504035357730726421 #=#?#%###=?=#=#??%=##=?=#=?##%=??=?= 163145143162145164616263 646576646576 73656372657421 twtktmsztytlsqwyxy 57696e74657232303133 ustqtlsvtusxwxwzwywy wqwu 6368616e6765 143157155160141156171616263 146151162145 163157155145144141171 tltusvsstksxtotqtlts swsytnswtusxsttusxwxwzwzwu 7365637265743121 170160 537072696e6732303134 6e6574776f726b696e67 #%=%#=#? 141144155151156 7870 70617373776f7264313233 #%?%#%%##=?%#%#? 12010065651676016214441 16316115462606071 #=?=#%###%?=#=###=?%#%%##=#?#=%# ?=%#?=## #=?=#=%##=?=#%?##%#?#%=##%%##%=% #=#?#%###=?=#=#?#=#?#%###=?=#=#? 74657374696e67313233 #%?##%#?#%=##%%##%=% 737072696e6732303137 143150141156147145 12316515515514516262606161 tysusvsutmtlwxwzwyws".split(' ')
# hint = 'rETwKtXdNrgIdKGNvhuXWXqtkOpcfzTEKKvQcNzIsPxLgyvQMxOWnDZOunIyujxcNnbsvbOqwoYmUtlWlBUfyGDLXIOoVcyqyMkcjQbKBNUtabauLFHZLqaNOSvVvrFhbkWdHWsdrjkAcxvViRfkGGLTTFkShPujVXgunhBmPCvmugHeTVDXKhVwHvPuftKdmlZJIBrI'
ascii_lower = string.ascii_lowercase
ascii_higher = string.ascii_uppercase

def dec_a(s):
    return bytes.fromhex(s).decode('utf-8')

b_chars = 'zyxwvutsrqponmlkjihgfedcba'
def dec_b(s):
    res = ''
    for i in range(0, len(s), 2):
        front = b_chars.find(s[i])
        back = b_chars.find(s[i+1])
        bin = f'{front:04b}' + f'{back:04b}'
        res += chr(int(bin, 2))
    return res

c_chars = '?#%='
def dec_c(s):
    result = ""
    for i in range(0, len(s), 4):
        binary_chunk = ""
        for j in range(4):
            binary_chunk += f'{c_chars.index(s[i + j]):02b}'
        result += chr(int(binary_chunk, 2))
    return result
    
# def dec_d(s):
#     s = [s[i:i+2] for i in range(0, len(s), 2)]
#     return "".join(chr(int(i, 8)) for i in s)

def decode_octal(encoded_str):
    octal_chunks = [encoded_str[i:i+3] for i in range(0, len(encoded_str), 3)]
    decoded_str = "".join(chr(int(chunk, 8)) for chunk in octal_chunks)
    return decoded_str

answer = b""
for i in range(len(encoded)):
    if hint[i*2] in ascii_lower and hint[i*2+1] in ascii_lower:
        answer += dec_a(encoded[i]).encode() + b' '
    elif hint[i*2] in ascii_lower and hint[i*2+1] in ascii_higher:
        answer += dec_b(encoded[i]).encode() + b' '
    elif hint[i*2] in ascii_higher and hint[i*2+1] in ascii_lower:
        answer += dec_c(encoded[i]).encode() + b' '
    elif hint[i*2] in ascii_higher and hint[i*2+1] in ascii_higher:
        answer += decode_octal(encoded[i]).encode() + b' '

print(answer)
r.sendlineafter(b'Enter the answer: ', answer[:-1])
r.interactive()