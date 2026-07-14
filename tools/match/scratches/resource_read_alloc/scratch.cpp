#include "crimsonland_resource.h"

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
