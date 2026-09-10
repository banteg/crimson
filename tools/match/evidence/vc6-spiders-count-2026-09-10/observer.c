#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef BOOL (__stdcall *protect_t)(LPVOID, DWORD, DWORD, PDWORD);
static HANDLE trace_file, decision_file, use_file;
static unsigned long targets[13];
static unsigned long addition_node, quotient_symbol, use_pass;

static void write_block(void *data, unsigned long size)
{
    DWORD written;
    if (!WriteFile(trace_file, data, size, &written, 0) || written != size)
        ExitProcess(99);
}

/* Record the unchanged operands at the address-folding decision's callsites. */
static void __cdecl observe_decision(unsigned long phase, unsigned long *registers)
{
    unsigned long node = phase == 4 ? registers[1] : registers[6];
    unsigned long base = registers[2], destination, symbol, record[12];
    DWORD written;
    if (node != addition_node) return;
    destination = *(unsigned long *)(node + 0x1c);
    symbol = *(unsigned long *)(destination + 0x14);
    record[0] = phase;
    record[1] = node;
    record[2] = *(unsigned long *)(node + 4);
    record[3] = *(unsigned char *)(destination + 8);
    record[4] = symbol;
    record[5] = symbol ? *(unsigned long *)(symbol + 0x14) : 0;
    record[6] = base ? *(unsigned char *)(base + 8) : 0;
    record[7] = base ? *(unsigned long *)(base + 0x14) : 0;
    record[8] = record[7] ? *(unsigned long *)(record[7] + 0x14) : 0;
    record[9] = base ? *(unsigned long *)(base + 0x18) : 0;
    record[10] = record[7] == symbol;
    record[11] = registers[4];
    if (!WriteFile(decision_file, record, sizeof(record), &written, 0)
        || written != sizeof(record)) ExitProcess(99);
}

/* Follow the count's real uses during C2+0x5b30's backward traversal. */
static void __cdecl observe_use(unsigned long phase, unsigned long *registers)
{
    unsigned long node, source, destination, symbol, source_kind, record[12];
    DWORD written;
    if (phase == 9) {
        ++use_pass;
        return;
    }
    if (!addition_node || !use_pass) ExitProcess(98);
    symbol = *(unsigned long *)(*(unsigned long *)(addition_node + 0x1c) + 0x14);
    node = registers[6];
    source = *(unsigned long *)(node + 0x18);
    destination = *(unsigned long *)(node + 0x1c);
    source_kind = source ? *(unsigned char *)(source + 8) : 0;
    record[5] = (source_kind == 1 || source_kind == 2)
        && *(unsigned long *)(source + 0x14) == symbol;
    record[6] = node == addition_node;
    if (!record[5] && !record[6]) return;
    record[0] = use_pass;
    record[1] = node;
    record[2] = *(unsigned long *)(node + 4);
    record[3] = *(unsigned short *)(node + 0x10);
    record[4] = destination ? *(unsigned char *)(destination + 8) : 0;
    record[7] = *(unsigned long *)(symbol + 0x14);
    record[8] = *(unsigned long *)(symbol + 0x4c);
    record[9] = *(unsigned long *)(symbol + 0x50);
    record[10] = source_kind;
    record[11] = symbol;
    if (!WriteFile(use_file, record, sizeof(record), &written, 0)
        || written != sizeof(record)) ExitProcess(99);
}

/* Read only the instruction list. The trampoline preserves registers/flags. */
static void __cdecl observe(unsigned long phase, unsigned long *registers)
{
    unsigned long *function = (unsigned long *)registers[6];
    unsigned long first = *(unsigned long *)(*(unsigned long *)function[2] + 0x1c);
    unsigned long node = first, count = 0, record[10], source, destination;
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
        source = (*(unsigned char *)(node + 9) & 1) ? *(unsigned long *)(node + 0x18) : 0;
        destination = (*(unsigned char *)(node + 9) & 1) ? *(unsigned long *)(node + 0x1c) : 0;
        record[3] = source ? *(unsigned char *)(source + 8) : 0;
        record[4] = source ? *(unsigned long *)(source + 0x14) : 0;
        record[5] = destination ? *(unsigned char *)(destination + 8) : 0;
        record[6] = destination ? *(unsigned long *)(destination + 0x14) : 0;
        record[7] = destination ? *(unsigned long *)(destination + 0x18) : 0;
        record[8] = source ? *(unsigned long *)(source + 0x18) : 0;
        if ((phase == 0 || phase == 7) && record[1] == 0x175 && record[2] == 35)
            quotient_symbol = record[6];
        if ((phase == 0 || phase == 7) && record[1] == 0x16d && record[2] == 35
            && record[4] == quotient_symbol) {
            if (addition_node && addition_node != node) ExitProcess(98);
            addition_node = node;
        }
        record[9] = (record[5] == 1 || record[5] == 2)
            ? *(unsigned long *)(record[6] + 0x14) : 0;
        write_block(record, sizeof(record));
    }
}

__declspec(naked) static void before_first_pass(void)
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

__declspec(naked) static void before_address_pass(void)
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

__declspec(naked) static void after_address_pass(void)
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

__declspec(naked) static void before_allocation(void)
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

__declspec(naked) static void lea_decision(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 4
        call observe_decision
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 16]
    }
}

__declspec(naked) static void add_input(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 5
        call observe_decision
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 20]
    }
}

__declspec(naked) static void add_decision(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 6
        call observe_decision
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 24]
    }
}

__declspec(naked) static void before_global_optimization(void)
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

__declspec(naked) static void after_global_optimization(void)
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

__declspec(naked) static void before_use_pass(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 9
        call observe_use
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 36]
    }
}

__declspec(naked) static void visit_count_uses(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 10
        call observe_use
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 40]
    }
}

__declspec(naked) static void before_temporary_conversion(void)
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

__declspec(naked) static void after_temporary_conversion(void)
{
    __asm {
        pushfd
        pushad
        mov eax, esp
        push eax
        push 12
        call observe
        add esp, 8
        popad
        popfd
        jmp dword ptr [targets + 48]
    }
}

void __stdcall start(void)
{
    static unsigned long sites[] = {0x58249, 0x582e1, 0x582fd, 0x583c5, 0x2ba57, 0x2ba97, 0x2bac1, 0x581ee, 0x581fc, 0x61fe, 0x5bf5, 0x13189, 0x13190};
    static unsigned long offsets[] = {0x281cd, 0x2930f, 0x294f3, 0x336f4, 0x26cd5, 0x02a48, 0x02a48, 0x130cb, 0xfcda, 0x5b30, 0x5c00, 0x11209, 0x1072b};
    static void (*hooks[])(void) = {
        before_first_pass, before_address_pass, after_address_pass, before_allocation, lea_decision, add_input, add_decision,
        before_global_optimization, after_global_optimization, before_use_pass, visit_count_uses,
        before_temporary_conversion, after_temporary_conversion
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
    decision_file = CreateFileA("decisions.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (decision_file == INVALID_HANDLE_VALUE) ExitProcess(94);
    use_file = CreateFileA("uses.bin", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (use_file == INVALID_HANDLE_VALUE) ExitProcess(94);
    for (i = 0; i < 13; ++i) {
        site = base + sites[i];
        targets[i] = (unsigned long)base + offsets[i];
        if (site[0] != 0xe8 || (unsigned long)(site + 5) + *(long *)(site + 1) != targets[i])
            ExitProcess(95);
        if (!protect(site, 5, PAGE_EXECUTE_READWRITE, &old)) ExitProcess(96);
        *(long *)(site + 1) = (long)hooks[i] - (long)site - 5;
    }
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    CloseHandle(trace_file);
    CloseHandle(decision_file);
    CloseHandle(use_file);
    if (!addition_node) ExitProcess(98);
    ExitProcess(result);
}
