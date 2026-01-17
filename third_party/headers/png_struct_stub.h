#ifndef PNG_STRUCT_STUB_H
#define PNG_STRUCT_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char png_byte;
typedef unsigned short png_uint_16;
typedef unsigned int png_uint_32;
typedef int png_int_32;
typedef unsigned int png_size_t;
typedef png_byte *png_bytep;
typedef void *png_voidp;

typedef struct png_struct_def png_struct;
typedef png_struct *png_structp;

typedef void (*png_error_ptr)(png_structp, const char *);
typedef void (*png_rw_ptr)(png_structp, png_bytep, png_uint_32);
typedef void (*png_read_status_ptr)(png_structp, png_uint_32, int);
typedef void (*png_write_status_ptr)(png_structp, png_uint_32, int);
typedef void (*png_progressive_info_ptr)(png_structp, png_voidp);
typedef void (*png_progressive_row_ptr)(png_structp, png_bytep, png_uint_32, int);
typedef void (*png_progressive_end_ptr)(png_structp, png_voidp);

typedef struct png_color_struct {
    png_byte red;
    png_byte green;
    png_byte blue;
} png_color;

typedef png_color *png_colorp;

typedef struct png_color_16_struct {
    png_byte index;
    png_uint_16 red;
    png_uint_16 green;
    png_uint_16 blue;
    png_uint_16 gray;
} png_color_16;

typedef struct png_row_info_struct {
    png_uint_32 width;
    png_uint_32 rowbytes;
    png_byte color_type;
    png_byte bit_depth;
    png_byte channels;
    png_byte pixel_depth;
} png_row_info;

typedef struct png_zstream_stub {
    png_uint_32 words[14];
} z_stream;

/* libpng 1.0.5-era layout (minimal fields for typing) */
struct png_struct_def {
    png_uint_32 jmpbuf[16];
    png_error_ptr error_fn;
    png_error_ptr warning_fn;
    png_voidp error_ptr;
    png_rw_ptr write_data_fn;
    png_rw_ptr read_data_fn;
    png_voidp io_ptr;

    png_uint_32 mode;
    png_uint_32 flags;
    png_uint_32 transformations;

    z_stream zstream;
    png_bytep zbuf;
    png_size_t zbuf_size;
    png_int_32 zlib_level;
    png_int_32 zlib_method;
    png_int_32 zlib_window_bits;
    png_int_32 zlib_mem_level;
    png_int_32 zlib_strategy;

    png_uint_32 width;
    png_uint_32 height;
    png_uint_32 num_rows;
    png_uint_32 usr_width;
    png_uint_32 rowbytes;
    png_uint_32 iwidth;
    png_uint_32 row_number;
    png_bytep prev_row;
    png_bytep row_buf;
    png_bytep sub_row;
    png_bytep up_row;
    png_bytep avg_row;
    png_bytep paeth_row;
    png_row_info row_info;

    png_uint_32 idat_size;
    png_uint_32 crc;
    png_colorp palette;
    png_uint_16 num_palette;
    png_uint_16 num_trans;
    png_uint_32 chunk_name_pad; /* observed padding before chunk_name */
    png_byte chunk_name[5];
    png_byte compression;
    png_byte filter;
    png_byte interlaced;
    png_byte pass;
    png_byte do_filter;
    png_byte color_type;
    png_byte bit_depth;
    png_byte usr_bit_depth;
    png_byte pixel_depth;
    png_byte channels;
    png_byte usr_channels;
    png_byte sig_bytes;
};

#ifdef __cplusplus
}
#endif

#endif
