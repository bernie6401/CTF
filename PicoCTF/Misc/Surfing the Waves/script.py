from scipy.io.wavfile import read
from tqdm import trange
# 讀取 WAV 檔案
# path = '//wsl.localhost/Ubuntu-20.04/home/sbk6401/CTF/PicoCTF/Misc/Surfing the Waves'
path = '.'
rate, data = read(path + "/main.wav")

decode_dic = {
    10 : "0",
    15 : "1",
    20 : "2",
    25 : "3",
    30 : "4",
    35 : "5",
    40 : "6",
    45 : "7",
    50 : "8",
    55 : "9",
    60 : "A",
    65 : "B",
    70 : "C",
    75 : "D",
    80 : "E",
    85 : "F",
}

message = ''
for i in trange(len(data)):
    message += decode_dic[data[i] // 100]
    # print(data[i], ' -> ', decode_dic[data[i] // 100])

# print(message)
print(bytes.fromhex(message).decode())