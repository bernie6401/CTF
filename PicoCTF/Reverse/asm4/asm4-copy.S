global asm4
section .text

asm4:
	asm_0:	push   ebp
	asm_1:	mov    ebp,esp
	asm_3:	push   ebx
	asm_4:	sub    esp,0x10
	asm_7:	mov    DWORD  [ebp-0x10],0x27a
	asm_14:	mov    DWORD  [ebp-0xc],0x0
	asm_21:	jmp    asm_27
	asm_23:	add    DWORD  [ebp-0xc],0x1
	asm_27:	mov    edx,DWORD  [ebp-0xc]
	asm_30:	mov    eax,DWORD  [ebp+0x8]
	asm_33:	add    eax,edx
	asm_35:	movzx  eax,BYTE  [eax]
	asm_38:	test   al,al
	asm_40:	jne    asm_23
	asm_42:	mov    DWORD  [ebp-0x8],0x1
	asm_49:	jmp    asm_138
	asm_51:	mov    edx,DWORD  [ebp-0x8]
	asm_54:	mov    eax,DWORD  [ebp+0x8]
	asm_57:	add    eax,edx
	asm_59:	movzx  eax,BYTE  [eax]
	asm_62:	movsx  edx,al
	asm_65:	mov    eax,DWORD  [ebp-0x8]
	asm_68:	lea    ecx,[eax-0x1]
	asm_71:	mov    eax,DWORD  [ebp+0x8]
	asm_74:	add    eax,ecx
	asm_76:	movzx  eax,BYTE  [eax]
	asm_79:	movsx  eax,al
	asm_82:	sub    edx,eax
	asm_84:	mov    eax,edx
	asm_86:	mov    edx,eax
	asm_88:	mov    eax,DWORD  [ebp-0x10]
	asm_91:	lea    ebx,[edx+eax*1]
	asm_94:	mov    eax,DWORD  [ebp-0x8]
	asm_97:	lea    edx,[eax+0x1]
	asm_100:	mov    eax,DWORD  [ebp+0x8]
	asm_103:	add    eax,edx
	asm_105:	movzx  eax,BYTE  [eax]
	asm_108:	movsx  edx,al
	asm_111:	mov    ecx,DWORD  [ebp-0x8]
	asm_114:	mov    eax,DWORD  [ebp+0x8]
	asm_117:	add    eax,ecx
	asm_119:	movzx  eax,BYTE  [eax]
	asm_122:	movsx  eax,al
	asm_125:	sub    edx,eax
	asm_127:	mov    eax,edx
	asm_129:	add    eax,ebx
	asm_131:	mov    DWORD  [ebp-0x10],eax
	asm_134:	add    DWORD  [ebp-0x8],0x1
	asm_138:	mov    eax,DWORD  [ebp-0xc]
	asm_141:	sub    eax,0x1
	asm_144:	cmp    DWORD  [ebp-0x8],eax
	asm_147:	jl     asm_51
	asm_149:	mov    eax,DWORD  [ebp-0x10]
	asm_152:	add    esp,0x10
	asm_155:	pop    ebx
	asm_156:	pop    ebp
	asm_157:	ret    

