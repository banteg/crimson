#include <windows.h>

int reg_write_dword(HKEY key, char *name, unsigned int value)
{
    return RegSetValueExA(
               key,
               name,
               0,
               REG_DWORD,
               (BYTE *)&value,
               sizeof(value))
            == ERROR_SUCCESS
        ? S_OK
        : E_FAIL;
}
