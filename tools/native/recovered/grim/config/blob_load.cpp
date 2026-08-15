#include "crimsonland_gameplay.h"

struct _iobuf;
typedef struct _iobuf FILE;

extern "C" __declspec(dllimport) FILE *__cdecl fopen(
    const char *path, const char *mode);
extern "C" __declspec(dllimport) int __cdecl fseek(
    FILE *file, long offset, int origin);
extern "C" __declspec(dllimport) long __cdecl ftell(FILE *file);
extern "C" __declspec(dllimport) unsigned int __cdecl fread(
    void *buffer, unsigned int size, unsigned int count, FILE *file);
extern "C" __declspec(dllimport) int __cdecl fclose(FILE *file);

extern crimson_cfg_t grim_config_blob;

bool grim_config_blob_save(void);

bool grim_config_blob_load(void)
{
    FILE *file = fopen("crimson.cfg", "rb");
    if (file == 0) {
        grim_config_blob_save();
        file = fopen("crimson.cfg", "rb");
        if (file == 0) {
            return false;
        }
    }

    fseek(file, 0, 2);
    if (ftell(file) != sizeof(grim_config_blob)) {
        fclose(file);
        grim_config_blob_save();
        return true;
    }

    fseek(file, 0, 0);
    fread(&grim_config_blob, sizeof(grim_config_blob), 1, file);
    fclose(file);
    return true;
}
