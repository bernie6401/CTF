enc_code = [  0xD2, 0x0E, 0x62, 0xD4, 0x04, 0x6B, 0x93, 0x0A, 0xC2, 0x74, 0x40, 0x87, 0xE4, 0xBF, 0xB0, 0xB1, 0xE1, 0x40, 0xC7, 0x83, 0xB4, 0x87, 0x40, 0xC2, 0x7F, 0x87, 0x87, 0x87, 0x87, 0x04, 0xFA, 0x7F, 0xA7, 0xF8, 0xD1, 0x0C, 0xC2, 0x7F, 0x0C, 0x9B, 0x02, 0xE7, 0xC6, 0xC7, 0x87, 0x0C, 0xD2, 0x7F, 0x0C, 0xC2, 0x8F, 0x86, 0x57, 0x88, 0x31, 0x87, 0x0F, 0xC2, 0x6C, 0x0C, 0xCA, 0x7F, 0x3D, 0xE0, 0xE1, 0xE1, 0xE1, 0x0E, 0x4F, 0x70, 0x6D, 0x56, 0x7D, 0x0E, 0x4F, 0x46, 0x7F, 0x98, 0xAE, 0x45, 0x0E, 0x57, 0x0E, 0x45, 0x46, 0x65, 0x85, 0x86, 0x45, 0x0E, 0x4F, 0xAE, 0x57, 0x88, 0x31, 0xC3, 0x82, 0x74, 0xB5, 0xC2, 0x6C, 0x88, 0x39, 0x47, 0xBE, 0x44, 0xF3, 0x80, 0x3F, 0x87, 0x87, 0x87, 0x87, 0x6C, 0x8C, 0x04, 0xC2, 0x7F, 0x86, 0x6C, 0x23, 0x3F, 0x86, 0x87, 0x87, 0x87, 0x04, 0x43, 0x93, 0xDC, 0xDA, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

real_code = []
for i in range(0x84):
    real_code.append("{:02x}".format(enc_code[i] ^ 0x87))
print(" ".join(real_code))