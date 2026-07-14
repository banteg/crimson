#ifndef CRIMSONLAND_RESOURCE_H
#define CRIMSONLAND_RESOURCE_H

#include <stdio.h>

extern char *buffer_reader_data;
extern int buffer_reader_size;
extern int buffer_reader_offset;
extern char resource_pack_path_buf[];
extern char resource_pack_entry_name_buf[];
extern FILE *resource_fp;
extern unsigned char resource_pack_enabled;

void buffer_reader_init(void *data, int size);
void buffer_reader_seek(int offset);
unsigned short buffer_reader_read_u16(void);
unsigned int buffer_reader_read_u32(void);
void buffer_reader_skip(int count);
unsigned char buffer_reader_find_tag(char *tag, int tag_len);
unsigned char resource_pack_read_cstring(FILE *fp);
unsigned char resource_pack_set(char *path);
unsigned char resource_open_read(char *path, unsigned int *size_out);
void resource_close(void);
unsigned char resource_read_alloc(
    char *path,
    void **out_data,
    unsigned int *out_size);

#endif
