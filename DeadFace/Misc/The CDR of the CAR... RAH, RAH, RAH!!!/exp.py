option = ['ascent','xray','yarbrough','jackal','minstrel','nevermore','outcast','kitten','victor','pugnacious','wallaby','savant','zarf','tango','ultimatum','papyrus','quill','renegade','llama','ghost','hellscape','industrious','zombification','bestial','cadre','dark','efficacious','foundational']

def car(a): return a[0]
def cdr(a): return a[1:]

expected_output = ['pugnacious', 'wallaby', 'savant', 'zarf']

# print(cdr(car(cdr(car(car(cdr (cdr(car(car(cdr(cdr(car(((('ascent'),('xray'),((('yarbrough','jackal'),('minstrel','nevermore'),((('outcast','kitten'),('victor','pugnacious','wallaby','savant','zarf'),('tango','ultimatum','papyrus')),('quill','renegade','llama'),('ghost','hellscape','industrious'))),('zombification','bestial','cadre')),('dark','efficacious')),('foundational')))))))))))))))

print(cdr(car(cdr(car(car(cdr(cdr(car(car(cdr(cdr(car (((('ascent'),('xray'),((('yarbrough','jackal'),('minstrel','nevermore'),((('outcast','kitten'),('victor','pugnacious','wallaby','savant','zarf'),('tango','ultimatum','papyrus')),('quill','renegade','llama')),('ghost','hellscape','industrious')),('zombification','bestial','cadre')),('dark','efficacious')),('foundational')))))))))))))))