mov dl, byte [ADDR]
sub esp, 0x20
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
xor ebp, ebp
test edi, edi
mov dword [ADDR], esi
jle L66
mov ecx, dword [ADDR]
mov eax, ADDR
mov ebx, dword [eax+0x4]
test ebx, ebx
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
jl L3f
pop edi
pop esi
pop ebp
pop ebx
add esp, 0x20
ret
lea eax, dword [ebp+ebp*2]
mov dword [esp+0x20], 0x0
mov dword [esp+0x24], 0x0
lea esi, dword [eax*8+ADDR]
mov eax, dword [esi+0x14]
mov ecx, dword [esp+0x20]
mov edx, dword [esp+0x24]
xor ebx, ebx
test eax, eax
mov dword [esp+0x18], ecx
mov dword [esp+0x1c], edx
jle L145
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
fld dword [esi]
fcomp dword [ADDR]
fnstsw ax
test ah, 0x1
jne Le8
fild dword [ADDR]
fcomp dword [esi]
fnstsw ax
test ah, 0x1
jne Le8
fild dword [esp+0x10]
test bl, 0x1
fstp dword [esp+0x18]
je Lff
fld dword [esp+0x18]
fchs
fstp dword [esp+0x18]
jmp Lff
fild dword [esp+0x10]
test bl, 0x1
fstp dword [esp+0x1c]
je Lff
fld dword [esp+0x1c]
fchs
fstp dword [esp+0x1c]
fld dword [esp+0x18]
fadd dword [esi]
mov eax, dword [edi+-0x4]
mov edx, dword [edi]
lea ecx, dword [esp+0x28]
push eax
fstp dword [esp+0x2c]
fld dword [esp+0x20]
fadd dword [esi+0x4]
push ecx
push edx
fstp dword [esp+0x38]
call ADDR
mov ecx, dword [esp+0x1c]
mov eax, dword [esi+0x14]
add esp, 0xc
inc ebx
add ecx, 0x28
cmp ebx, eax
mov dword [esp+0x10], ecx
jl Lb1
mov edi, dword [ADDR]
lea eax, dword [edi+-0x1]
mov dword [esi+0x14], 0x0
cmp ebp, eax
mov byte [ADDR], 0x0
jge L66
mov ecx, dword [esi+0x10]
mov eax, dword [esi+0x28]
cmp ecx, eax
jne L66
inc ebp
add esi, 0x18
jmp L89
