#include "crimsonland_resource.h"

unsigned char buffer_reader_find_tag(char *tag, int tag_len)
{
    int scan;

    for (scan = 0; scan < buffer_reader_size; ++scan) {
        int i;

        for (i = 0; i < tag_len; ++i) {
            if (buffer_reader_data[scan + i] != tag[i]) {
                break;
            }
        }
        if (i == tag_len) {
            buffer_reader_offset = scan + tag_len;
            return 1;
        }
    }
    return 0;
}
