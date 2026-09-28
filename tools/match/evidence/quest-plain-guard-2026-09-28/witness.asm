mov dl, byte [ADDR]
sub esp, 0x1c
test dl, dl
push ebx
push ebp
push esi
push edi
je L20
mov esi, dword [ADDR]
mov eax, dword [ADDR]
add esi, eax
jmp L22
xor esi, esi
mov edi, dword [ADDR]
xor ebx, ebx
xor ebp, ebp
cmp edi, ebx
mov dword [ADDR], esi
jle L66
mov ecx, dword [ADDR]
mov eax, ADDR
cmp dword [eax+0x4], ebx
jle L5e
cmp dword [eax], ecx
jl L6e
test dl, dl
je L5e
cmp esi, 0xbb8
jle L5e
cmp ecx, 0x6a4
jg L6e
inc ebp
add eax, 0x18
cmp ebp, edi
jl L41
pop edi
pop esi
pop ebp
pop ebx
add esp, 0x1c
ret
lea eax, dword [ebp+ebp*2]
mov dword [esp+0x1c], 0x0
mov dword [esp+0x20], 0x0
lea esi, dword [eax*8+ADDR]
mov eax, dword [esi+0x14]
mov ecx, dword [esp+0x1c]
mov edx, dword [esp+0x20]
cmp eax, ebx
mov dword [esp+0x14], ecx
mov dword [esp+0x18], edx
jle L143
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
fld dword [esi]
fcomp dword [ADDR]
fnstsw ax
test ah, 0x1
jne Le6
fild dword [ADDR]
fcomp dword [esi]
fnstsw ax
test ah, 0x1
jne Le6
fild dword [esp+0x10]
test bl, 0x1
fstp dword [esp+0x14]
je Lfd
fld dword [esp+0x14]
fchs
fstp dword [esp+0x14]
jmp Lfd
fild dword [esp+0x10]
test bl, 0x1
fstp dword [esp+0x18]
je Lfd
fld dword [esp+0x18]
fchs
fstp dword [esp+0x18]
fld dword [esp+0x14]
fadd dword [esi]
mov eax, dword [edi+-0x4]
mov edx, dword [edi]
lea ecx, dword [esp+0x24]
push eax
fstp dword [esp+0x28]
fld dword [esp+0x1c]
fadd dword [edi+-0x8]
push ecx
push edx
fstp dword [esp+0x34]
call ADDR
mov ecx, dword [esp+0x1c]
mov eax, dword [esi+0x14]
add esp, 0xc
inc ebx
add ecx, 0x28
cmp ebx, eax
mov dword [esp+0x10], ecx
jl Laf
mov edi, dword [ADDR]
lea eax, dword [edi+-0x1]
xor ebx, ebx
cmp ebp, eax
mov dword [esi+0x14], ebx
mov byte [ADDR], bl
jge L66
mov ecx, dword [esi+0x10]
mov eax, dword [esi+0x28]
cmp ecx, eax
jne L66
inc ebp
add esi, 0x18
jmp L89
