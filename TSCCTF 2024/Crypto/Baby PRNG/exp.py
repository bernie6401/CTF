from os import urandom


def h(a, m):
    return (-a*a-m*m+0x6861616368616d61)&1

class H:
    def __init__(self, a, ac) -> None:
        self.a = a
        self.ac = ac

    def ha(self):
        m = sum([h(self.ac[i], self.a[i]) for i in range(len(self.a))])&1
        a = self.ac[0]
        self.ac = self.ac[1:] + [m]
        return a

def decode_binary_string(encoded_str):
    decoded_str = ""
    for i in range(0, len(encoded_str), 8):
        chunk = encoded_str[i:i+8]
        decoded_str += chr(int(chunk, 2))
    return decoded_str

output = "1101001001001000111111101000111010001000010000000010010000011000101111000101000100011001110000101000011000000100000111110101001101101100111101101000010100001110101101001100010111110001001001011011101111100011101101011010011111100111001000111000000101000111000001011111111000111001111100000111000101010011011101110000110101100010100011001000101110110010001010110010110111100111111010100110100000110000001011110100011011001010011101000011010001001100111100010011111111101010101101000101100011110010111011111010000101110000011111000000011110010110101010011100000111110111100000101100101100011110101110100010011111101010110111010001111011110101100001110101000101000001011101101101110110001001011011100001111001111101110000011101111001010100000010011001000111100101000100110101101100111000010010111111111010111000111000101001111000001010111010111110001001011011111100110000010111100110101111000110111011001100010110010101010010011111011010001111101101111000101011110100000011001100100011100110001001000000101100001000000110010010101100100000110101101110110100110110000000100111001110101101001010100001111011111010011101011100000011000011100001101101000111111111011000001111100111010000001100100001111111011110001001101010011000000100001110111110001011001000010000111000010010110011011100101010100110100100001001010101010111111110001011100011110001011010001110000101001110000011011101011110001100010010111011101111001010011010010100110000111010010001011000111101011101111000110010110000010000101000010001100111110111011111010101100010110110101001110110001010011010101010001100101100010000110101101100001111110001111001001001110010010010000001010100111010111110100111011100000111100100011101101011111001110100110111000010110000000111100100000100001110110101100010100101010000100011100101011011111101000011101000010010011011111001011000010110000000010101011001110110110110001110000001101000010010110011011000001010001110110101001011010100101100110010010111100111110010001101011111101011101101101111011001000101011001101101110111000110001000001110000000000111010001100010011001011010001111011011100101111000100011110011101100101100001011000010011010011000010110110101111001"
a = [0, 2, 17, 19, 23, 37, 41, 53]
ch = H(a, list(map(int, f'{int.from_bytes(urandom(8), "big"):064b}')))
a = [ch.ha() for _ in range(len(output)+52)]

decoded_flag = []
for i in range(len(output)):
    decoded_flag.append(int(output[i]) ^ a[i])

decoded_binary_str = ''.join([str(bit) for bit in decoded_flag])
decoded_str = decode_binary_string(decoded_binary_str)

print(decoded_str)
