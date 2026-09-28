#include <windows.h>
#include <string.h>

extern "C" HRESULT win32_file_get_version_words(
    char *file_path,
    ULARGE_INTEGER *file_version);
extern "C" ULARGE_INTEGER dx_version_pack_4x16(
    WORD major,
    WORD minor,
    WORD patch_major,
    WORD patch_minor);
extern "C" int dx_version_compare_4x16(
    ULARGE_INTEGER current,
    ULARGE_INTEGER required);

#define LOAD_VERSION(suffix) \
    strcpy(file, system_path); \
    strcat(file, suffix)

#define SET_VERSION(version_major, version_minor, version_letter) \
    if (major) *major = version_major; \
    if (minor) *minor = version_minor; \
    if (letter) *letter = version_letter; \
    found = TRUE

extern "C" HRESULT dx_get_version_fallback_from_files(
    DWORD *major,
    DWORD *minor,
    char *letter)
{
    ULARGE_INTEGER file_version;
    char system_path[512];
    char file[512];
    BOOL found = FALSE;

    if (GetSystemDirectoryA(system_path, MAX_PATH) != 0) {
        system_path[MAX_PATH - 1] = 0;

        LOAD_VERSION("\\ddraw.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 2, 0, 95)) >= 0) {
                SET_VERSION(1, 0, ' ');
            }

            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 3, 0, 1096)) >= 0) {
                SET_VERSION(2, 0, ' ');
            }

            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 4, 0, 68)) >= 0) {
                SET_VERSION(3, 0, ' ');
            }
        }

        LOAD_VERSION("\\d3drg8x.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 4, 0, 70)) >= 0) {
                SET_VERSION(3, 0, 'a');
            }
        }

        LOAD_VERSION("\\ddraw.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 5, 0, 155)) >= 0) {
                SET_VERSION(5, 0, ' ');
            }

            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 6, 0, 318)) >= 0) {
                SET_VERSION(6, 0, ' ');
            }

            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 6, 0, 436)) >= 0) {
                SET_VERSION(6, 1, ' ');
            }
        }

        LOAD_VERSION("\\dplayx.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 6, 3, 518)) >= 0) {
                SET_VERSION(6, 1, 'a');
            }
        }

        LOAD_VERSION("\\ddraw.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 7, 0, 700)) >= 0) {
                SET_VERSION(7, 0, ' ');
            }
        }

        LOAD_VERSION("\\dinput.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(4, 7, 0, 716)) >= 0) {
                SET_VERSION(7, 0, 'a');
            }
        }

        LOAD_VERSION("\\ddraw.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if ((HIWORD(file_version.HighPart) == 4
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(4, 8, 0, 400)) >= 0)
                || (HIWORD(file_version.HighPart) == 5
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(5, 1, 2258, 400)) >= 0)) {
                SET_VERSION(8, 0, ' ');
            }
        }

        LOAD_VERSION("\\d3d8.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if ((HIWORD(file_version.HighPart) == 4
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(4, 8, 1, 881)) >= 0)
                || (HIWORD(file_version.HighPart) == 5
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(5, 1, 2600, 881)) >= 0)) {
                SET_VERSION(8, 1, ' ');
            }

            if ((HIWORD(file_version.HighPart) == 4
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(4, 8, 1, 901)) >= 0)
                || (HIWORD(file_version.HighPart) == 5
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(5, 1, 2600, 901)) >= 0)) {
                SET_VERSION(8, 1, 'a');
            }
        }

        LOAD_VERSION("\\mpg2splt.ax");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if (dx_version_compare_4x16(
                    file_version,
                    dx_version_pack_4x16(6, 3, 1, 885)) >= 0) {
                SET_VERSION(8, 1, 'b');
            }
        }

        LOAD_VERSION("\\dpnet.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            if ((HIWORD(file_version.HighPart) == 4
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(4, 9, 0, 134)) >= 0)
                || (HIWORD(file_version.HighPart) == 5
                    && dx_version_compare_4x16(
                        file_version,
                        dx_version_pack_4x16(5, 2, 3677, 134)) >= 0)) {
                SET_VERSION(8, 2, ' ');
            }
        }

        LOAD_VERSION("\\d3d9.dll");
        if (SUCCEEDED(
                win32_file_get_version_words(file, &file_version))) {
            SET_VERSION(9, 0, ' ');
        }
    }

    if (!found) {
        if (major != 0) {
            *major = 0;
        }
        if (minor != 0) {
            *minor = 0;
        }
        if (letter != 0) {
            *letter = ' ';
        }
    }

    return S_OK;
}

#undef SET_VERSION
#undef LOAD_VERSION
