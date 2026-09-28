#include <io.h>

extern "C" long crt_findfirst(char *pattern, _finddata_t *finddata);
extern "C" int crt_findnext(long handle, _finddata_t *finddata);
extern "C" int crt_findclose(long handle);

extern "C" bool mods_any_available(void)
{
    int count = 0;
    _finddata_t finddata;
    long handle = crt_findfirst("mods\\*.dll", &finddata);
    if (handle != -1 && finddata.name != 0) {
        do {
            ++count;
        } while (crt_findnext(handle, &finddata) == 0);
    }
    crt_findclose(handle);
    return count != 0;
}
