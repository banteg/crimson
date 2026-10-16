#include <stdio.h>

extern unsigned char grim_lookup_blob_loaded;
extern char *grim_lookup_blob;
extern int grim_lookup_blob_size;

bool grim_lookup_blob_load(char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == 0) {
        grim_lookup_blob_loaded = false;
        if (grim_lookup_blob != 0) {
            delete[] grim_lookup_blob;
        }
        grim_lookup_blob = 0;
        return false;
    }

    fseek(file, 0, 2);
    grim_lookup_blob_size = ftell(file);
    fseek(file, 0, 0);

    grim_lookup_blob = new char[grim_lookup_blob_size + 1];
    fread(grim_lookup_blob, grim_lookup_blob_size, 1, file);
    fclose(file);
    return true;
}
