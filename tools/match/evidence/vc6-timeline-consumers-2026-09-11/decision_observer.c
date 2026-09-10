#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[16];
static unsigned long return_sites[4], watched_temp, pending[4][12];
static HANDLE decision_file;

static void write_block(void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(trace_file, data, size, &written, 0) || written != size)
        ExitProcess(99);
}


/* Capture the seven common operand words and every operand-chain element.
   Raw flags are retained without assigning undocumented meanings. */
static void __cdecl observe(unsigned long phase, unsigned long *registers)
{
    unsigned long *function = (unsigned long *)registers[6];
    unsigned long first = *(unsigned long *)(*(unsigned long *)function[2] + 0x1c);
    unsigned long node = first, count = 0, record[230], op, side, j, k, at;
    while (node && count < 4096) { ++count; node = *(unsigned long *)node; }
    if (node) ExitProcess(97);
    if (phase == 9) {
        unsigned long n = first, dest;
        watched_temp = 0;
        while (n) {
            if (*(unsigned short *)(n+0x10) == 40 && *(unsigned long *)(n+4) == 1) {
                dest = *(unsigned long *)(n+0x1c);
                if (dest && *(unsigned char *)(dest+8) == 1)
                    watched_temp = *(unsigned long *)(dest+0x18);
            }
            n = *(unsigned long *)n;
        }
    }
    if (phase == 9 && watched_temp) {
        unsigned long row[12]; DWORD written;
        for(j=0;j<12;++j) row[j]=0;
        row[0]=0x100+phase; row[1]=watched_temp; row[2]=watched_temp;
        row[3]=*(unsigned long *)(watched_temp+4);
        row[4]=*(unsigned long *)(watched_temp+0x38);
        row[5]=*(unsigned long *)(watched_temp+0x14);
        row[6]=*(unsigned long *)(watched_temp+0x30);
        if (!WriteFile(decision_file,row,sizeof(row),&written,0) || written!=sizeof(row)) ExitProcess(87);
    }
    write_block(&phase, 4);
    write_block(&count, 4);
    for (node = first; node; node = *(unsigned long *)node) {
        for (j=0;j<230;++j) record[j]=0;
        record[0]=node; record[1]=*(unsigned long *)(node+4);
        record[2]=*(unsigned short *)(node+0x10); record[3]=*(unsigned long *)(node+8);
        if (*(unsigned char *)(node+9)&1) {
            for (side=0;side<2;++side) {
                op=*(unsigned long *)(node+0x18+side*4);
                at=4+side*113;
                for (k=0;op && k<16;++k) {
                    for (j=0;j<7;++j) record[at+1+k*7+j]=*(unsigned long *)(op+j*4);
                    op=*(unsigned long *)op;
                }
                if(op) ExitProcess(98);
                record[at]=k;
            }
        }
        write_block(record,sizeof(record));
    }
}
static void __cdecl decision_before(unsigned long index, unsigned long *regs)
{
    unsigned long temp, definition = regs[6], dest, src;
    unsigned long *row = pending[index];
    if (index < 2) {
        temp = *(unsigned long *)(regs[3]+12);
        row[4]=regs[6]; row[5]=regs[5];
        row[6]=*(unsigned long *)(regs[5]+4);
        row[7]=*(unsigned short *)(regs[5]+0x10);
        row[8]=*(unsigned long *)(regs[3]+8);
    } else {
        dest=*(unsigned long *)(definition+0x1c);
        src=*(unsigned long *)(definition+0x18);
        temp=*(unsigned long *)(dest+0x18);
        row[4]=definition; row[5]=src;
        row[6]=*(unsigned long *)(definition+4);
        row[7]=*(unsigned short *)(definition+0x10);
        row[8]=src ? *(unsigned char *)(src+8) : 0;
    }
    row[0]=index; row[1]=temp; row[2]=watched_temp;
    row[3]=*(unsigned long *)(temp+4);
    row[9]=0; row[10]=0; row[11]=0;
}
static void __cdecl decision_after(unsigned long index, unsigned long *regs)
{
    DWORD written;
    pending[index][9]=regs[7];
    pending[index][10]=*(unsigned long *)(pending[index][1]+4);
    if (!WriteFile(decision_file, pending[index], sizeof(pending[index]), &written, 0)
        || written != sizeof(pending[index])) ExitProcess(89);
}
__declspec(naked) static void decision_0(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 0
        call decision_before
        add esp, 8
        popad
        popfd
        push eax
        mov eax, dword ptr [esp+4]
        mov dword ptr [return_sites+0], eax
        mov dword ptr [esp+4], offset after_0
        pop eax
        jmp dword ptr [targets+48]
    after_0:
        pushfd
        pushad
        mov eax, esp
        push eax
        push 0
        call decision_after
        add esp, 8
        popad
        popfd
        jmp dword ptr [return_sites+0]
    }
}
__declspec(naked) static void decision_1(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 1
        call decision_before
        add esp, 8
        popad
        popfd
        push eax
        mov eax, dword ptr [esp+4]
        mov dword ptr [return_sites+4], eax
        mov dword ptr [esp+4], offset after_1
        pop eax
        jmp dword ptr [targets+52]
    after_1:
        pushfd
        pushad
        mov eax, esp
        push eax
        push 1
        call decision_after
        add esp, 8
        popad
        popfd
        jmp dword ptr [return_sites+4]
    }
}
__declspec(naked) static void decision_2(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 2
        call decision_before
        add esp, 8
        popad
        popfd
        push eax
        mov eax, dword ptr [esp+4]
        mov dword ptr [return_sites+8], eax
        mov dword ptr [esp+4], offset after_2
        pop eax
        jmp dword ptr [targets+56]
    after_2:
        pushfd
        pushad
        mov eax, esp
        push eax
        push 2
        call decision_after
        add esp, 8
        popad
        popfd
        jmp dword ptr [return_sites+8]
    }
}
__declspec(naked) static void decision_3(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 3
        call decision_before
        add esp, 8
        popad
        popfd
        push eax
        mov eax, dword ptr [esp+4]
        mov dword ptr [return_sites+12], eax
        mov dword ptr [esp+4], offset after_3
        pop eax
        jmp dword ptr [targets+60]
    after_3:
        pushfd
        pushad
        mov eax, esp
        push eax
        push 3
        call decision_after
        add esp, 8
        popad
        popfd
        jmp dword ptr [return_sites+12]
    }
}
__declspec(naked) static void phase_0(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 0
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 0]
    }
}

__declspec(naked) static void phase_1(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 1
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 4]
    }
}

__declspec(naked) static void phase_2(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 2
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 8]
    }
}

__declspec(naked) static void phase_3(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 3
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 12]
    }
}

__declspec(naked) static void phase_4(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 4
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 16]
    }
}

__declspec(naked) static void phase_5(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 5
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 20]
    }
}

__declspec(naked) static void phase_6(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 6
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 24]
    }
}

__declspec(naked) static void phase_7(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 7
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 28]
    }
}

__declspec(naked) static void phase_8(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 8
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 32]
    }
}

__declspec(naked) static void phase_9(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 9
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 36]
    }
}

__declspec(naked) static void phase_10(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 10
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 40]
    }
}

__declspec(naked) static void phase_11(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 11
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 44]
    }
}

void __stdcall start(void)
{
    static unsigned long sites[] = {0x581ee, 0x581fc, 0x58249, 0x582e1, 0x58310, 0x5831e, 0x5838c, 0x5839f, 0x2fbb0, 0x2fbbd, 0x2fbc4, 0x583c5, 0x3091c, 0x3097d, 0x307cd, 0x3086f};
    static unsigned long offsets[] = {0x130cb, 0xfcda, 0x281cd, 0x2930f, 0x29511, 0x296de, 0x26d75, 0x2f8fc, 0x30308, 0x306c1, 0x30a40, 0x336f4, 0x31a50, 0x31a50, 0x309bb, 0x309bb};
    static void (*hooks[])(void) = {phase_0, phase_1, phase_2, phase_3, phase_4, phase_5, phase_6, phase_7, phase_8, phase_9, phase_10, phase_11, decision_0, decision_1, decision_2, decision_3};
    HMODULE module;
    invoke_t invoke;
    protect_t protect;
    unsigned char *base, *site;
    unsigned long i;
    DWORD old;
    int result;
    if (!LoadLibraryA(pdb_path)) ExitProcess(90);
    module = LoadLibraryA(backend_path);
    if (!module) ExitProcess(91);
    invoke = (invoke_t)GetProcAddress(module, "_InvokeCompilerPass@12");
    if (!invoke) ExitProcess(92);
    base = (unsigned char *)invoke - 0x57444;
    protect = (protect_t)GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualProtect");
    if (!protect) ExitProcess(93);
    trace_file = CreateFileA("phases.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (trace_file == INVALID_HANDLE_VALUE) ExitProcess(94);
    decision_file = CreateFileA("decisions.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (decision_file == INVALID_HANDLE_VALUE) ExitProcess(88);
    for (i = 0; i < 16; ++i) {
        site = base + sites[i];
        targets[i] = (unsigned long)base + offsets[i];
        if (site[0] != 0xe8 || (unsigned long)(site + 5) + *(long *)(site + 1) != targets[i])
            ExitProcess(95);
        if (!protect(site, 5, PAGE_EXECUTE_READWRITE, &old)) ExitProcess(96);
        *(long *)(site + 1) = (long)hooks[i] - (long)site - 5;
    }
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    CloseHandle(decision_file);
    CloseHandle(trace_file);
    ExitProcess(result);
}
