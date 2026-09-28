#include "crimsonland_resource.h"

unsigned char resource_pack_read_cstring(FILE *fp)
{
    int offset = 0;

    while (!feof(fp)) {
        int ch = fgetc(fp);
        if (ch == 0) {
            break;
        }
        resource_pack_entry_name_buf[offset] = (char)ch;
        ++offset;
    }
    resource_pack_entry_name_buf[offset] = 0;
    return !feof(fp);
}
