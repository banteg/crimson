#include <windows.h>

int reg_read_dword_default(
    HKEY key,
    char *name,
    unsigned int *out,
    unsigned int fallback)
{
    DWORD type;
    DWORD size = sizeof(*out);

    if (RegQueryValueExA(key, name, 0, &type, (BYTE *)out, &size) != ERROR_SUCCESS) {
        *out = fallback;
    }
    return 0;
}
