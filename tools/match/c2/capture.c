/* Diagnostic /B2 wrapper. Copy the frontend files, then call unmodified C2. */
#include <windows.h>

typedef int (__stdcall *invoke_t)(int, char **, void *);
typedef void (__stdcall *abort_t)(int);

static HMODULE backend;
static char destination[MAX_PATH];
static char backend_path[MAX_PATH];

static DWORD text_length(const char *text)
{
    DWORD length = 0;
    while (text[length]) ++length;
    return length;
}

static int append(char *destination, const char *text)
{
    DWORD index = text_length(destination);
    if (index + text_length(text) >= MAX_PATH) return 0;
    while ((destination[index++] = *text++) != 0) {}
    return 1;
}

static int write_all(HANDLE file, const void *data, DWORD length)
{
    const char *cursor = (const char *)data;
    DWORD written;
    while (length) {
        if (!WriteFile(file, cursor, length, &written, 0) || !written) return 0;
        cursor += written;
        length -= written;
    }
    return 1;
}

static int copy_file(const char *source, const char *destination)
{
    char buffer[2048];
    DWORD length;
    int result = 1;
    HANDLE input = CreateFileA(source, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    HANDLE output;
    if (input == INVALID_HANDLE_VALUE) return 0;
    output = CreateFileA(destination, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    if (output == INVALID_HANDLE_VALUE) {
        CloseHandle(input);
        return 0;
    }
    for (;;) {
        if (!ReadFile(input, buffer, sizeof(buffer), &length, 0)) {
            result = 0;
            break;
        }
        if (!length) break;
        if (!write_all(output, buffer, length)) {
            result = 0;
            break;
        }
    }
    CloseHandle(output);
    CloseHandle(input);
    return result;
}

static int capture_prefix(const char *prefix)
{
    /* C2 opens these same four streams. Do not copy unrelated temporary files. */
    static const char *suffixes[] = {"ex", "in", "sy", "gl"};
    char source[MAX_PATH], target[MAX_PATH];
    const char *basename = prefix;
    const char *cursor;
    int index;
    for (cursor = prefix; *cursor; ++cursor) {
        if (*cursor == '\\' || *cursor == '/') basename = cursor + 1;
    }
    for (index = 0; index < 4; ++index) {
        source[0] = target[0] = 0;
        if (!append(source, prefix) || !append(source, suffixes[index])
            || !append(target, destination) || !append(target, "\\")
            || !append(target, basename) || !append(target, suffixes[index])
            || !copy_file(source, target)) return 0;
    }
    return 1;
}

__declspec(dllexport) int __stdcall InvokeCompilerPass(
    int argc, char **argv, void *context)
{
    char argument_path[MAX_PATH];
    HANDLE arguments;
    invoke_t invoke;
    DWORD length;
    int index, captured = 0, written = 1;
    length = GetEnvironmentVariableA("CRIMSON_IL_CAPTURE_DIR",
        destination, sizeof(destination));
    if (!length || length >= sizeof(destination)) return 80;
    length = GetEnvironmentVariableA("CRIMSON_IL_BACKEND",
        backend_path, sizeof(backend_path));
    if (!length || length >= sizeof(backend_path)) return 81;
    argument_path[0] = 0;
    if (!append(argument_path, destination)
        || !append(argument_path, "\\arguments.bin")) return 82;
    arguments = CreateFileA(argument_path, GENERIC_WRITE, 0, 0,
        CREATE_ALWAYS, 0, 0);
    if (arguments == INVALID_HANDLE_VALUE) return 83;
    for (index = 0; index < argc; ++index) {
        if (!write_all(arguments, argv[index], text_length(argv[index]) + 1)) {
            written = 0;
            break;
        }
    }
    CloseHandle(arguments);
    if (!written) return 84;
    for (index = 0; index + 1 < argc; ++index) {
        if (text_length(argv[index]) == 3 && argv[index][0] == '-'
            && argv[index][1] == 'i' && argv[index][2] == 'l') {
            if (captured || !capture_prefix(argv[index + 1])) return 85;
            captured = 1;
        }
    }
    if (!captured) return 86;
    backend = LoadLibraryA(backend_path);
    if (!backend) return 87;
    invoke = (invoke_t)GetProcAddress(backend, "_InvokeCompilerPass@12");
    if (!invoke) return 88;
    return invoke(argc, argv, context);
}

__declspec(dllexport) void __stdcall AbortCompilerPass(int reason)
{
    abort_t abort;
    if (!backend) return;
    abort = (abort_t)GetProcAddress(backend, "_AbortCompilerPass@4");
    if (abort) abort(reason);
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    return TRUE;
}
