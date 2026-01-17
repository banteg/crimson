#ifndef PNG_STRUCT_STUB_H
#define PNG_STRUCT_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int png_uint_32;
typedef unsigned char png_byte;
typedef png_byte *png_bytep;
typedef void *png_voidp;

typedef struct png_struct_def png_struct;
typedef png_struct *png_structp;

typedef void (*png_error_ptr)(png_structp, const char *);
typedef void (*png_rw_ptr)(png_structp, png_bytep, png_uint_32);
typedef void (*png_row_callback_ptr)(png_structp, png_uint_32, int);

typedef struct png_zstream_stub {
    png_uint_32 words[14];
} png_zstream_stub;

struct png_struct_def {
    int jmpbuf[16];
    png_error_ptr error_fn;
    png_error_ptr warning_fn;
    png_voidp error_ptr;
    png_rw_ptr write_data_fn;
    png_rw_ptr read_data_fn;
    png_voidp io_ptr;
    png_uint_32 mode;
    png_uint_32 flags;
    png_uint_32 transformations;
    png_zstream_stub zstream;
    png_bytep zbuf;
    png_uint_32 zbuf_size;
    png_uint_32 pad_a4[5];
    png_uint_32 bit_depth;
    png_uint_32 color_type;
    png_uint_32 pad_c0;
    png_uint_32 pad_c4;
    png_uint_32 width;
    png_uint_32 height;
    png_uint_32 rowbytes;
    png_uint_32 pass;
    png_bytep row_buf;
    png_bytep prev_row;
    png_uint_32 pad_e0;
    png_uint_32 pad_e4;
    png_uint_32 pad_e8;
    png_uint_32 pad_ec;
    png_uint_32 pad_f0;
    png_uint_32 pixel_depth;
    png_uint_32 pad_f8;
    png_uint_32 idat_size;
    png_uint_32 pad_100;
    png_uint_32 pad_104;
    png_uint_32 pad_108;
    png_uint_32 chunk_name;
    png_uint_32 pad_110;
    png_uint_32 current_pass;
    png_uint_32 pad_118;
    png_uint_32 pad_11c;
    png_uint_32 pad_120;
    png_uint_32 pad_124;
    png_uint_32 pad_128;
    png_uint_32 pad_12c;
    png_uint_32 pad_130;
    png_uint_32 pad_134;
    png_uint_32 palette_entries;
    png_uint_32 pad_13c;
    png_uint_32 pad_140;
    png_voidp palette;
    png_uint_32 pad_148;
    png_uint_32 pad_14c;
    png_uint_32 pad_150;
    png_uint_32 pad_154;
    png_uint_32 pad_158;
    png_uint_32 pad_15c;
    png_uint_32 pad_160;
    png_uint_32 pad_164;
    png_uint_32 pad_168;
    png_row_callback_ptr row_callback_fn;
};

#ifdef __cplusplus
}
#endif

#endif
