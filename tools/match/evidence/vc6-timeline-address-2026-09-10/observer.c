#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file;
static unsigned long targets[4];

static void write_block(void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(trace_file, data, size, &written, 0) || written != size)
        ExitProcess(99);
}

/* Read only the instruction list. The trampoline preserves registers/flags. */
static void __cdecl observe(unsigned long phase, unsigned long *registers)
{
    unsigned long *function = (unsigned long *)registers[6];
    unsigned long first = *(unsigned long *)(*(unsigned long *)function[2] + 0x1c);
    unsigned long node = first, count = 0, record[3];
    while (node && count < 4096) {
        ++count;
        node = *(unsigned long *)node;
    }
    if (node) ExitProcess(97);
    write_block(&phase, 4);
    write_block(&count, 4);
    for (node = first; node; node = *(unsigned long *)node) {
        record[0] = node;
        record[1] = *(unsigned long *)(node + 4);
        record[2] = *(unsigned long *)(node + 0x10) & 0xffff;
        write_block(record, sizeof(record));
    }
}

__declspec(naked) static void before_30308(void)
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
        jmp dword ptr [targets]
    }
}

__declspec(naked) static void before_306c1(void)
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

__declspec(naked) static void after_306c1(void)
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

__declspec(naked) static void before_336f4(void)
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

void __stdcall start(void)
{
    static unsigned long sites[] = {0x2fbb0, 0x2fbbd, 0x2fbc4, 0x583c5};
    static unsigned long offsets[] = {0x30308, 0x306c1, 0x30a40, 0x336f4};
    static void (*hooks[])(void) = {
        before_30308, before_306c1, after_306c1, before_336f4
    };
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
    for (i = 0; i < 4; ++i) {
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
