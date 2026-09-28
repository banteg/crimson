#include <windows.h>

extern "C" HRESULT win32_file_get_version_words(
    char *file_path,
    unsigned int *version_words)
{
    if (file_path == 0 || version_words == 0) {
        return E_INVALIDARG;
    }

    DWORD ignored_handle;
    UINT info_size = GetFileVersionInfoSizeA(file_path, &ignored_handle);
    if (info_size > 0) {
        unsigned char *info_data = new unsigned char[info_size];
        if (info_data == 0) {
            return E_OUTOFMEMORY;
        }

        if (GetFileVersionInfoA(file_path, 0, info_size, info_data)) {
            VS_FIXEDFILEINFO *fixed_info = 0;
            if (VerQueryValueA(
                    info_data,
                    "\\",
                    (void **)&fixed_info,
                    &info_size)
                && fixed_info != 0) {
                version_words[1] = fixed_info->dwFileVersionMS;
                version_words[0] = fixed_info->dwFileVersionLS;
                delete[] info_data;
                return S_OK;
            }
        }

        delete[] info_data;
    }
    return E_FAIL;
}
