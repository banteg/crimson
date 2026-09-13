/* Standalone backend entry; replay_settings.h is generated from captured argv. */
#include <windows.h>
#include "replay_settings.h"

typedef int (__stdcall *invoke_t)(int, char **, void *);

void __stdcall start(void)
{
    HMODULE module;
    invoke_t invoke;
    int result;
    /* Match CL's compiler-directory dependency search before loading C2. */
    if (!LoadLibraryA(pdb_path)) ExitProcess(90);
    module = LoadLibraryA(backend_path);
    if (!module) ExitProcess(91);
    invoke = (invoke_t)GetProcAddress(module, "_InvokeCompilerPass@12");
    if (!invoke) ExitProcess(92);
    result = invoke(sizeof(arguments) / sizeof(arguments[0]), arguments, 0);
    ExitProcess(result);
}
