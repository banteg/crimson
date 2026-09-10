#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[12];

static void write_block(void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(trace_file, data, size, &written, 0) || written != size)
        ExitProcess(99);
}


static void __cdecl observe(unsigned long phase, unsigned long *registers)
{
    unsigned long *function = (unsigned long *)registers[6];
    unsigned long first = *(unsigned long *)(*(unsigned long *)function[2] + 0x1c);
    unsigned long node = first, count = 0, record[16], op, side, j;
    while (node && count < 4096) { ++count; node = *(unsigned long *)node; }
    if (node) ExitProcess(97);
    write_block(&phase, 4);
    write_block(&count, 4);
    for (node = first; node; node = *(unsigned long *)node) {
        for (j=0;j<16;++j) record[j]=0;
        record[0]=node; record[1]=*(unsigned long *)(node+4);
        record[2]=*(unsigned short *)(node+0x10); record[3]=*(unsigned long *)(node+8);
        if (*(unsigned char *)(node+9)&1) {
            for (side=0;side<2;++side) {
                op=*(unsigned long *)(node+0x18+side*4);
                if (!op) continue;
                record[4+side*6]=op;
                record[5+side*6]=*(unsigned char *)(op+8);
                record[6+side*6]=*(unsigned long *)(op+0x10);
                record[7+side*6]=*(unsigned long *)(op+0x14);
                record[8+side*6]=*(unsigned long *)(op+0x18);
                record[9+side*6]=*(unsigned long *)op;
            }
        }
        write_block(record,sizeof(record));
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
    static unsigned long sites[] = {0x581ee, 0x581fc, 0x58249, 0x582e1, 0x58310, 0x5831e, 0x5838c, 0x5839f, 0x2fbb0, 0x2fbbd, 0x2fbc4, 0x583c5};
    static unsigned long offsets[] = {0x130cb, 0xfcda, 0x281cd, 0x2930f, 0x29511, 0x296de, 0x26d75, 0x2f8fc, 0x30308, 0x306c1, 0x30a40, 0x336f4};
    static void (*hooks[])(void) = {phase_0, phase_1, phase_2, phase_3, phase_4, phase_5, phase_6, phase_7, phase_8, phase_9, phase_10, phase_11};
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
    for (i = 0; i < 12; ++i) {
        site = base + sites[i];
        targets[i] = (unsigned long)base + offsets[i];
        if (site[0] != 0xe8 || (unsigned long)(site + 5) + *(long *)(site + 1) != targets[i])
            ExitProcess(95);
        if (!protect(site, 5, PAGE_EXECUTE_READWRITE, &old)) ExitProcess(96);
        *(long *)(site + 1) = (long)hooks[i] - (long)site - 5;
    }
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    CloseHandle(trace_file);
    ExitProcess(result);
}
