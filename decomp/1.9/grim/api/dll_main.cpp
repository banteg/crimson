#include <windows.h>
#if CL_BUILD == 10908
#include <stdio.h>
#include <stdlib.h>
#endif

extern HINSTANCE grim_module_handle;
extern HICON grim_window_icon_handle;

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        grim_module_handle = hinstDLL;
        grim_window_icon_handle =
            LoadIconA(hinstDLL, MAKEINTRESOURCEA(0x72));
#if CL_BUILD == 10908
        // 1.9.8 checksums crimsonland.exe and compares it with the value
        // last recorded in updates.dat; a mismatch appends the new sum and
        // fails the load.
        FILE *file = fopen("crimsonland.exe", "rb");
        if (file == 0) {
            MessageBoxA(
                0,
                "Files are missing; please get a new\ninstall package from "
                "www.crimsonland.com",
                "Grim",
                MB_OK);
            return FALSE;
        }

        char buffer[1024] = {0};
        int checksum = 0;
        int block = 0;
        while (!feof(file)) {
            int count = fread(buffer, 1, sizeof(buffer), file);
            ++block;
            for (int i = 0; i < count; ++i) {
                checksum += buffer[i] * count * 7 * block
                    + (count + 1) * 111 * block + 3;
            }
        }
        fclose(file);

        file = fopen("updates.dat", "rb");
        int recorded = 12;
        if (file != 0) {
            fread(&recorded, 4, 1, file);
            fread(&recorded, 4, 1, file);
            fread(&recorded, 4, 1, file);
            fclose(file);
        }
        if (abs(checksum) != abs(recorded)) {
            file = fopen("updates.dat", "ab");
            if (file != 0) {
                fwrite(&checksum, 4, 1, file);
                fclose(file);
            }
            return FALSE;
        }
#endif
    }
    return TRUE;
}
