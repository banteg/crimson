/*
 * Matcher-only adaptations of libpng 1.0.5 routines.
 * Copyright (c) 1995, 1996 Guy Eric Schalnat, Group 42, Inc.
 * Copyright (c) 1996, 1997 Andreas Dilger.
 * Copyright (c) 1998, 1999 Glenn Randers-Pehrson.
 *
 * Function names are changed to keep scratch objects isolated. The complete
 * libpng 1.0.5 copyright and permission notice is preserved in
 * third_party/headers/png.h.
 */
#define PNG_INTERNAL
#include "../../../third_party/headers/png.h"

struct grim_png_source_t {
    png_byte fields_000[0x5c];
    png_uint_32 flags;
    png_uint_32 transformations;
    png_byte fields_064[0x58];
    png_uint_32 height;
    png_uint_32 num_rows;
    png_byte fields_0c4[0x4f];
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
    png_byte fields_11d;
    png_uint_16 filler;
    png_byte fields_120[0x10];
    float gamma;
    float screen_gamma;
};

extern "C" void grim_png_read_update_info(
    grim_png_source_t *png_ptr, png_infop info_ptr)
{
    if (!(png_ptr->flags & PNG_FLAG_ROW_INIT))
        png_read_start_row((png_structp)png_ptr);
    png_read_transform_info((png_structp)png_ptr, info_ptr);
}

extern "C" void grim_png_read_image(
    grim_png_source_t *png_ptr, png_bytepp image)
{
    png_uint_32 i, image_height;
    int pass, j;
    png_bytepp rp;

    pass = png_set_interlace_handling((png_structp)png_ptr);
    image_height = png_ptr->height;
    png_ptr->num_rows = image_height;

    for (j = 0; j < pass; j++) {
        rp = image;
        for (i = 0; i < image_height; i++) {
            png_read_row((png_structp)png_ptr, *rp, NULL);
            rp++;
        }
    }
}

extern "C" void grim_png_set_filler(
    grim_png_source_t *png_ptr, png_uint_32 filler, int filler_loc)
{
    png_ptr->transformations |= PNG_FILLER;
    png_ptr->filler = (png_byte)filler;
    if (filler_loc == PNG_FILLER_AFTER)
        png_ptr->flags |= PNG_FLAG_FILLER_AFTER;
    else
        png_ptr->flags &= ~PNG_FLAG_FILLER_AFTER;

    if (png_ptr->color_type == PNG_COLOR_TYPE_RGB)
        png_ptr->usr_channels = 4;

    if (png_ptr->color_type == PNG_COLOR_TYPE_GRAY && png_ptr->bit_depth >= 8)
        png_ptr->usr_channels = 2;
}

extern "C" void grim_png_do_swap(png_row_infop row_info, png_bytep row)
{
    if (row_info->bit_depth == 16) {
        png_bytep rp = row;
        png_uint_32 i;
        png_uint_32 istop = row_info->width * row_info->channels;

        for (i = 0; i < istop; i++, rp += 2) {
            png_byte t = *rp;
            *rp = *(rp + 1);
            *(rp + 1) = t;
        }
    }
}

extern "C" void grim_png_set_gamma(
    grim_png_source_t *png_ptr, double scrn_gamma, double file_gamma)
{
    if (fabs(scrn_gamma * file_gamma - 1.0) > PNG_GAMMA_THRESHOLD)
        png_ptr->transformations |= PNG_GAMMA;
    png_ptr->gamma = (float)file_gamma;
    png_ptr->screen_gamma = (float)scrn_gamma;
}

extern "C" void grim_png_do_chop(png_row_infop row_info, png_bytep row)
{
    if (row_info->bit_depth == 16) {
        png_bytep sp = row;
        png_bytep dp = row;
        png_uint_32 i;
        png_uint_32 istop = row_info->width * row_info->channels;

        for (i = 0; i < istop; i++, sp += 2, dp++)
            *dp = *sp;

        row_info->bit_depth = 8;
        row_info->pixel_depth = (png_byte)(8 * row_info->channels);
        row_info->rowbytes = row_info->width * row_info->channels;
    }
}

extern "C" voidpf grim_png_zalloc(voidpf png_ptr, uInt items, uInt size)
{
    png_uint_32 num_bytes = (png_uint_32)items * size;
    png_voidp ptr = (png_voidp)png_malloc((png_structp)png_ptr, num_bytes);

    if (ptr == NULL)
        return NULL;

    if (num_bytes > (png_uint_32)0x8000L) {
        png_memset(ptr, 0, (png_size_t)0x8000L);
        png_memset(
            (png_bytep)ptr + (png_size_t)0x8000L,
            0,
            (png_size_t)(num_bytes - (png_uint_32)0x8000L));
    } else {
        png_memset(ptr, 0, (png_size_t)num_bytes);
    }
    return (voidpf)ptr;
}

extern "C" png_infop grim_png_create_info_struct(png_structp png_ptr)
{
    png_infop info_ptr;

    if (png_ptr == NULL)
        return NULL;
    if ((info_ptr = (png_infop)png_create_struct(PNG_STRUCT_INFO)) != NULL)
        png_memset(info_ptr, 0, 0x40);

    return info_ptr;
}

extern "C" png_voidp grim_png_memcpy_check(
    png_structp png_ptr,
    png_voidp s1,
    png_voidp s2,
    png_uint_32 length)
{
    png_size_t size = (png_size_t)length;
    if ((png_uint_32)size != length)
        png_error(png_ptr, "Overflow in png_memcpy_check.");
    return png_memcpy(s1, s2, size);
}

extern "C" png_voidp grim_png_memset_check(
    png_structp png_ptr,
    png_voidp s1,
    int value,
    png_uint_32 length)
{
    png_size_t size = (png_size_t)length;
    if ((png_uint_32)size != length)
        png_error(png_ptr, "Overflow in png_memset_check.");
    return png_memset(s1, value, size);
}
