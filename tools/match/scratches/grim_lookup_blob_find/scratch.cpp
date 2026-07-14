#include <string.h>

extern char *grim_lookup_blob_magic;
extern char *grim_lookup_blob;
extern int grim_lookup_blob_size;

char *grim_lookup_blob_find(char *path)
{
    int offset = strlen(grim_lookup_blob_magic) + 1;
    if (offset >= grim_lookup_blob_size) {
        return 0;
    }

    char *blob = grim_lookup_blob;
    while (offset < grim_lookup_blob_size) {
        int name_length = strlen(blob + offset);

        if (strcmp(blob + offset, path) == 0) {
            return blob + name_length + offset + 5;
        }

        int payload_size = *(int *)(blob + name_length + offset + 1);
        offset += name_length + payload_size + 5;
    }

    return 0;
}
