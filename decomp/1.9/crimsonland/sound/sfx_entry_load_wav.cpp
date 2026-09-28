#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

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
