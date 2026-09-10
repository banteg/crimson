#include <windows.h>
#include "replay_settings.h"
typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[8];

static void write_block(void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(trace_file, data, size, &written, 0) || written != size)
        ExitProcess(99);
}

/* Read instruction identity, opcode, IL line and operand storage owners only. */
static void __cdecl observe(unsigned long phase, unsigned long *registers)
{
    unsigned long *function = (unsigned long *)registers[6];
    unsigned long first = *(unsigned long *)(*(unsigned long *)function[2] + 0x1c);
    unsigned long node = first, count = 0, source, destination, record[7];
    while (node && count < 4096) { ++count; node = *(unsigned long *)node; }
    if (node) ExitProcess(97);
    write_block(&phase, 4);
    write_block(&count, 4);
    for (node = first; node; node = *(unsigned long *)node) {
        source = (*(unsigned char *)(node + 9) & 1) ? *(unsigned long *)(node + 0x18) : 0;
        destination = (*(unsigned char *)(node + 9) & 1) ? *(unsigned long *)(node + 0x1c) : 0;
        record[0] = node;
        record[1] = *(unsigned long *)(node + 4);
        record[2] = *(unsigned short *)(node + 0x10);
        record[3] = source ? *(unsigned char *)(source + 8) : 0;
        record[4] = source ? *(unsigned long *)(source + 0x18) : 0;
        record[5] = destination ? *(unsigned char *)(destination + 8) : 0;
        record[6] = destination ? *(unsigned long *)(destination + 0x18) : 0;
        write_block(record, sizeof(record));
    }
}

__declspec(naked) static void hook_0(void)
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

__declspec(naked) static void hook_1(void)
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

__declspec(naked) static void hook_2(void)
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

__declspec(naked) static void hook_3(void)
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

__declspec(naked) static void hook_4(void)
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

__declspec(naked) static void hook_5(void)
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

__declspec(naked) static void hook_6(void)
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

__declspec(naked) static void hook_7(void)
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

void __stdcall start(void)
{
    static unsigned long sites[] = {0x58310, 0x5831e, 0x583b2, 0x583c5, 0x583e9, 0x58479, 0x584a9, 0x58541};
    static unsigned long offsets[] = {0x29511, 0x296de, 0x2fb58, 0x336f4, 0x337ec, 0x3536c, 0x35042, 0x3e113};
    static void (*hooks[])(void) = {hook_0, hook_1, hook_2, hook_3, hook_4, hook_5, hook_6, hook_7};
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
    for (i = 0; i < 8; ++i) {
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
