from z3 import *

# patters = [[('sub', 20935)], [('sub', 31575), ('lsh', 9), ('add', 45363), ('add', 35372), ('sub', 15465)], [('add', 19123), ('add', 35260), ('sub', 49421), ('lsh', 8)], [('lsh', 1), ('sub', 4977), ('sub', 55837)], [('add', 16937)], [('sub', 56984), ('lsh', 2), ('sub', 32363), ('sub', 46293)], [('sub', 94), ('sub', 48860), ('sub', 18342), ('lsh', 3)], [('add', 37549), ('sub', 36283), ('lsh', 6), ('add', 6253)], [('add', 34661), ('sub', 13281), ('sub', 64107)], [('sub', 8525), ('sub', 30349), ('sub', 26744)], [('lsh', 2), ('sub', 18120), ('sub', 63091), ('add', 17287), ('sub', 37618), ('add', 2237)], [('sub', 48573), ('sub', 4449), ('add', 36013), ('sub', 64051)], [('add', 10415), ('lsh', 3), ('lsh', 10)], [('add', 5676), ('lsh', 3), ('lsh', 10), ('add', 32002), ('sub', 60775)], [('add', 35939), ('sub', 32666), ('sub', 45639), ('add', 2077), ('sub', 16253)], [('sub', 30392), ('sub', 26913), ('sub', 14009), ('sub', 62416)], [('sub', 15056), ('sub', 40527)], [('lsh', 5)], [('lsh', 1), ('sub', 16070)], [('add', 2045)], [('lsh', 8), ('add', 37087), ('sub', 22013), ('lsh', 10), ('lsh', 2)], [('add', 31880), ('sub', 56557), ('lsh', 6), ('lsh', 5), ('lsh', 8), ('add', 15535)], [('add', 22937), ('add', 4060)], [('add', 8462), ('sub', 4463), ('sub', 45810), ('lsh', 1)], [('sub', 10144), ('lsh', 8), ('lsh', 5), ('lsh', 1), ('lsh', 8)], [('add', 49937), ('lsh', 2), ('add', 60982), ('sub', 24799)], [('lsh', 4), ('add', 53340), ('add', 50619), ('sub', 56111), ('add', 6134), ('lsh', 1)], [('sub', 22577), ('sub', 50645)], [('add', 21265), ('sub', 41440)], [('add', 63314), ('sub', 45755), ('add', 62216)], [('sub', 52616)], [('add', 21192)], [('add', 62573), ('sub',18811)], [('add', 35452), ('sub', 11573), ('sub', 49079), ('sub', 36361), ('sub', 26862), ('lsh', 9)], [('add', 13610), ('lsh', 7), ('lsh', 3), ('sub', 28490), ('lsh', 10), ('add', 44742)], [('lsh', 10), ('sub', 1797), ('sub', 10564), ('add', 12394)], [('add', 45165), ('lsh', 10), ('sub', 60610), ('sub', 63002), ('sub', 14851), ('lsh', 1)], [('add', 34840), ('lsh', 3), ('sub', 16907)], [('add', 4404), ('lsh', 3), ('lsh', 7), ('lsh', 6)], [('lsh', 6), ('add', 51738), ('sub', 24621), ('add', 58646)], [('lsh', 1)], [('add', 29375), ('sub', 419), ('add', 2854), ('sub', 11878), ('lsh', 10), ('add', 40151)], [('add', 22953)]]
patterns = 
targets = [0x26, 0x19, 0xCC, 0x33, 0xAA, 0x04, 0x14, 0xFE, 0xFC, 0x82, 
  0x85, 0x75, 0x5F, 0x87, 0x82, 0x81, 0x1B, 0xAE, 0xD8, 0x90, 
  0xDB, 0x51, 0x4C, 0xC0, 0x1A, 0x52, 0x5F, 0x2D, 0x37, 0x41, 
  0x49, 0xD5, 0xAD, 0x65, 0x53, 0x24, 0xC3, 0x1A, 0x74, 0x80, 
  0x33, 0xEC, 0x7D]
flag_len = 43

# 起手式 - 開一個Solver
s = Solver()

# 建立符號 - 以此lab來說就是建立43個符號對應每一個flag字元
bvs = [BitVec(f'bt_{i}', 8) for i in range(flag_len)]

# 加上constraint - 以此lab來說每一個flag字元都應該限制在空白到0x7f之間
for bv in bvs:
    s.add(And(bv >= 0x20, bv <= 0x7f))


for i, patter in enumerate(patterns):
    formula = f'bvs[{i}]'

    for step in patter:
        op = step[0]
        value = step[1]

        if op == 'add':
            formula = f'({formula} + {value})'
        elif op == 'sub':
            formula = f'({formula} - {value})'
        elif op == 'lsh':
            formula = f'({formula} << {value})'

    print(f'{formula} == {targets[i]}')
    s.add(eval(formula) == targets[i])

# 如果有解的話就會做以下操作
if s.check() == sat:
    print('Find ~~~')
    print(s.model())

    flag = ""
    for bv in bvs:
        flag += chr(s.model()[bv].as_long())

    print(flag)
