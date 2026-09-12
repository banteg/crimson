mov dl, byte [ADDR]
sub esp, 0x20
test dl, dl
push ebx
push ebp
push esi
push edi
je L20
mov edi, dword [ADDR]
mov eax, dword [ADDR]
add edi, eax
jmp L22
xor edi, edi
mov ecx, dword [ADDR]
xor ebx, ebx
xor ebp, ebp
cmp ecx, ebx
mov dword [ADDR], edi
jle L66
mov esi, dword [ADDR]
mov eax, ADDR
cmp dword [eax+0x4], ebx
jle L5e
cmp dword [eax], esi
jl L6e
test dl, dl
je L5e
cmp edi, 0xbb8
jle L5e
cmp esi, 0x6a4
jg L6e
inc ebp
add eax, 0x18
cmp ebp, ecx
jl L41
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
mov eax, dword [esp+0x24]
mov edx, dword [esp+0x20]
mov dword [esp+0x1c], eax
mov eax, dword [esi+0x14]
cmp eax, ebx
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
fstp dword [esp+0x18]
je Lfd
fld dword [esp+0x18]
fchs
fstp dword [esp+0x18]
jmp Lfd
fild dword [esp+0x10]
test bl, 0x1
fstp dword [esp+0x1c]
je Lfd
fld dword [esp+0x1c]
fchs
fstp dword [esp+0x1c]
fld dword [esp+0x18]
fadd dword [esi]
mov ecx, dword [edi+-0x4]
mov eax, dword [edi]
lea edx, dword [esp+0x28]
push ecx
fstp dword [esp+0x2c]
fld dword [esp+0x20]
fadd dword [esi+0x4]
push edx
push eax
fstp dword [esp+0x38]
call ADDR
mov ecx, dword [esp+0x1c]
mov eax, dword [esi+0x14]
add esp, 0xc
inc ebx
add ecx, 0x28
cmp ebx, eax
mov dword [esp+0x10], ecx
jl Laf
mov ecx, dword [ADDR]
lea edx, dword [ecx+-0x1]
xor ebx, ebx
cmp ebp, edx
mov dword [esi+0x14], ebx
mov byte [ADDR], bl
jge L66
mov eax, dword [esi+0x10]
mov edx, dword [esi+0x28]
cmp eax, edx
jne L66
inc ebp
add esi, 0x18
jmp L89
