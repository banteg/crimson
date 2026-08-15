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
