#include "crimsonland_gameplay.h"

struct _iobuf;
typedef struct _iobuf FILE;

extern "C" __declspec(dllimport) FILE *__cdecl fopen(
    const char *path, const char *mode);
extern "C" __declspec(dllimport) unsigned int __cdecl fwrite(
    const void *buffer, unsigned int size, unsigned int count, FILE *file);
extern "C" __declspec(dllimport) int __cdecl fclose(FILE *file);

extern crimson_cfg_t grim_config_blob;

bool grim_config_blob_save(void)
{
    FILE *file = fopen("crimson.cfg", "wb");
    if (file != 0) {
        fwrite(&grim_config_blob, sizeof(grim_config_blob), 1, file);
        fclose(file);
    }
    return true;
}
