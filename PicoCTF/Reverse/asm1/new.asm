asm1:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	cmp    flag ,0x71c
	<+10>:	jg     0x512           <asm1+37>
	<+12>:	cmp    flag ,0x6cf
	<+19>:	jne    0x50a           <asm1+29>
	<+21>:	mov    eax, flag 
	<+24>:	add    eax,0x3
	<+27>:	jmp    0x529           <asm1+60>
	<+29>:	mov    eax, flag 
	<+32>:	sub    eax,0x3
	<+35>:	jmp    0x529           <asm1+60>
	<+37>:	cmp    flag ,0x8be
	<+44>:	jne    0x523           <asm1+54>
	<+46>:	mov    eax, flag 
	<+49>:	sub    eax,0x3
	<+52>:	jmp    0x529           <asm1+60>
	<+54>:	mov    eax, flag 
	<+57>:	add    eax,0x3
	<+60>:	pop    ebp
	<+61>:	ret    

