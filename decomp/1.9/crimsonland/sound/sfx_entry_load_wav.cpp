#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8. Its C2 (9044) reuses what it learned
 * compiling earlier functions of the same unit: resource_read_alloc precedes
 * this function there (see resource_read_alloc.cpp), so the entry stays in edi
 * and the data pointer in esi across the parse call. 1.9.93's C2 (8966)
 * ignores this, so the canonical object keeps one function per file.
 */
unsigned char resource_read_alloc(
    char *path,
    void **out_data,
    unsigned int *out_size)
{
    char *data;
    FILE *fp;

    if (!resource_open_read(path, out_size)) {
        return 0;
    }

    fp = resource_fp;
    data = new char[*out_size];
    fread(data, *out_size, 1, fp);
    resource_close();
    *out_data = data;
    return 1;
}
#endif

extern "C" unsigned char sfx_entry_load_wav(
    sfx_entry_t *entry,
    char *path)
{
    void *data;
    unsigned int size;

    if (!resource_read_alloc(path, &data, &size)) {
        return 0;
    }
    if (!wav_parse_into_entry(entry, data, size)) {
        crt_free(data);
        return 0;
    }
    crt_free(data);
    if (sfx_entry_create_buffers(entry)) {
        return 1;
    }
    return 0;
}
