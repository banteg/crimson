#include <windows.h>

extern "C" HRESULT dx_get_version_from_dxdiag(
    int *major,
    int *minor,
    char *letter);
extern "C" HRESULT dx_get_version_fallback_from_files(
    int *major,
    int *minor,
    char *letter);
extern "C" int crt_snprintf(
    char *buffer,
    int buffer_size,
    const char *format,
    ...);
extern "C" int crt_tolower(int character);

extern "C" HRESULT dx_get_version(
    int *version,
    char *version_text,
    int version_text_size)
{
    if (version != 0) {
        *version = 0;
    }
    if (version_text != 0 && version_text_size > 0) {
        *version_text = 0;
    }

    int major = 0;
    int minor = 0;
    char letter = ' ';
    if (dx_get_version_from_dxdiag(&major, &minor, &letter) < 0) {
        if (dx_get_version_fallback_from_files(&major, &minor, &letter) < 0) {
            return E_FAIL;
        }
    }

    letter = (char)crt_tolower(letter);
    if (version != 0) {
        int packed = ((major << 8) + minor) << 8;
        if (letter >= 'a' && letter <= 'z') {
            packed += letter - 0x60;
        }
        *version = packed;
    }

    if (version_text != 0 && version_text_size > 0) {
        if (letter == ' ') {
            crt_snprintf(
                version_text,
                version_text_size,
                "%d.%d",
                major,
                minor);
        } else {
            crt_snprintf(
                version_text,
                version_text_size,
                "%d.%d%c",
                major,
                minor,
                letter);
        }
        version_text[version_text_size - 1] = 0;
    }
    return S_OK;
}
