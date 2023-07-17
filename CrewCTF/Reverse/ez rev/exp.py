from z3 import *
s = Solver()

flag = [BitVec(f"flag[{i}]",8) for i in range(0x100)]
tmp = []
t = 0x69
for i in range(len(flag)):
    t = (flag[i]+i)^t
    tmp.append(t)
t = 0x96
for i in range(1,len(flag)):
    tmp[i] = ((tmp[i-1] - tmp[i]) ^ t)&0xff
    t = tmp[i]
enc = bytes.fromhex("0a07ee64058ef6943d85178411691c8902751f8c01830b85169a0e8c0084038517b30f9f3ce417b7609537f9d5af46a243b15aa07c62f96b06ad1dc93ef3e49332c31ea10ac31cd330d33cd03ece8bdf32c209cf81cd89c9f33295c480ba99e910e009dd3039743e655f3a2010c42c0812c824dc58736b5454736f2cf033d374bc33b73ca8d3fb34a4d3ff2ca0d3e354cc53c75cf8334b54f4334f6cd073b3349cf397fc88d39bf484d39fec80d383d4ec53e75c98f3abd494f3")

for i in range(len(enc)):
    s.add(enc[i] == tmp[i])
print(s.check())
m = s.model()
for d in m.decls():
    print("%s = %s"%(d.name(),m[d]))
flag = [0]*0x100
flag[5] = 116
flag[42] = 110
flag[175] = 0
flag[137] = 0
flag[34] = 98
flag[118] = 0
flag[65] = 114
flag[54] = 99
flag[23] = 111
flag[31] = 97
flag[38] = 111
flag[177] = 0
flag[55] = 105
flag[0] = 99
flag[120] = 0
flag[128] = 0
flag[62] = 111
flag[13] = 105
flag[180] = 0
flag[44] = 120
flag[25] = 95
flag[28] = 112
flag[50] = 101
flag[57] = 108
flag[27] = 111
flag[71] = 98
flag[33] = 95
flag[133] = 0
flag[158] = 0
flag[169] = 0
flag[115] = 125
flag[184] = 0
flag[140] = 0
flag[91] = 116
flag[24] = 119
flag[106] = 103
flag[59] = 121
flag[74] = 95
flag[170] = 0
flag[160] = 0
flag[49] = 95
flag[147] = 0
flag[69] = 114
flag[80] = 117
flag[93] = 105
flag[68] = 101
flag[97] = 111
flag[30] = 99
flag[101] = 114
flag[32] = 110
flag[4] = 99
flag[58] = 108
flag[10] = 108
flag[63] = 114
flag[159] = 0
flag[26] = 114
flag[168] = 0
flag[45] = 105
flag[29] = 95
flag[72] = 117
flag[64] = 95
flag[179] = 0
flag[99] = 95
flag[47] = 117
flag[108] = 100
flag[129] = 0
flag[119] = 0
flag[2] = 101
flag[39] = 95
flag[139] = 0
flag[11] = 108
flag[8] = 119
flag[149] = 0
flag[35] = 101
flag[3] = 119
flag[142] = 0
flag[131] = 0
flag[60] = 95
flag[178] = 0
flag[19] = 116
flag[22] = 110
flag[40] = 111
flag[113] = 101
flag[95] = 95
flag[121] = 0
flag[96] = 121
flag[134] = 0
flag[136] = 0
flag[141] = 0
flag[67] = 118
flag[145] = 0
flag[150] = 0
flag[73] = 116
flag[83] = 97
flag[151] = 0
flag[155] = 0
flag[172] = 0
flag[174] = 0
flag[14] = 95
flag[103] = 95
flag[132] = 0
flag[138] = 0
flag[163] = 0
flag[36] = 95
flag[78] = 121
flag[37] = 115
flag[109] = 95
flag[153] = 0
flag[107] = 111
flag[76] = 102
flag[125] = 0
flag[53] = 101
flag[85] = 95
flag[51] = 115
flag[173] = 0
flag[176] = 0
flag[181] = 0
flag[182] = 0
flag[18] = 110
flag[16] = 105
flag[104] = 97
flag[123] = 0
flag[61] = 102
flag[43] = 111
flag[126] = 0
flag[185] = 0
flag[6] = 102
flag[90] = 95
flag[148] = 0
flag[165] = 0
flag[48] = 115
flag[117] = 0
flag[164] = 0
flag[114] = 114
flag[98] = 117
flag[77] = 95
flag[79] = 111
flag[84] = 110
flag[88] = 110
flag[105] = 95
flag[122] = 0
flag[127] = 0
flag[111] = 101
flag[156] = 0
flag[81] = 95
flag[166] = 0
flag[21] = 107
flag[161] = 0
flag[183] = 0
flag[86] = 102
flag[171] = 0
flag[20] = 95
flag[87] = 105
flag[92] = 104
flag[46] = 111
flag[146] = 0
flag[12] = 95
flag[167] = 0
flag[157] = 0
flag[52] = 112
flag[56] = 97
flag[102] = 101
flag[130] = 0
flag[152] = 0
flag[89] = 100
flag[41] = 98
flag[162] = 0
flag[110] = 114
flag[144] = 0
flag[7] = 123
flag[17] = 100
flag[66] = 101
flag[82] = 99
flag[100] = 97
flag[1] = 114
flag[75] = 105
flag[116] = 0
flag[94] = 115
flag[124] = 0
flag[135] = 0
flag[143] = 0
flag[112] = 118
flag[9] = 101
flag[15] = 100
flag[70] = 95
flag[154] = 0

print(bytes(flag))