#ifndef CRIMSONLAND_RESOURCE_H
#define CRIMSONLAND_RESOURCE_H

extern char *buffer_reader_data;
extern int buffer_reader_size;
extern int buffer_reader_offset;

void buffer_reader_init(void *data, int size);
void buffer_reader_seek(int offset);
unsigned short buffer_reader_read_u16(void);
unsigned int buffer_reader_read_u32(void);
void buffer_reader_skip(int count);
unsigned char buffer_reader_find_tag(char *tag, int tag_len);

#endif
