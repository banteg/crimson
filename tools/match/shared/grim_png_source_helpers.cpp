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
    png_byte fields_000[0x58];
    png_uint_32 mode;
    png_uint_32 flags;
    png_uint_32 transformations;
    png_byte fields_064[0x38];
    png_bytep zbuf;
    png_size_t zbuf_size;
    png_byte fields_0a4[0x18];
    png_uint_32 height;
    png_uint_32 num_rows;
    png_byte fields_0c4[0x3c];
    png_uint_32 crc;
    png_byte fields_104[8];
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
    png_byte fields_11d;
    png_uint_16 filler;
    png_byte fields_120[0x10];
    float gamma;
    float screen_gamma;
};

struct grim_png_info_source_t {
    png_byte fields_00[8];
    png_uint_32 valid;
    png_byte fields_0c[0x0a];
    png_uint_16 num_trans;
    png_byte fields_18[0x18];
    png_bytep trans;
    png_color_16 trans_values;
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

extern "C" void grim_png_set_srgb_gamma(
    grim_png_source_t *png_ptr,
    grim_png_info_source_t *info_ptr,
    int intent)
{
    float file_gamma;

    if (png_ptr == NULL || info_ptr == NULL)
        return;

    png_set_sRGB((png_structp)png_ptr, (png_infop)info_ptr, intent);
    file_gamma = (float).45455;
    png_set_gAMA((png_structp)png_ptr, (png_infop)info_ptr, file_gamma);
}

extern "C" void grim_png_set_trns(
    grim_png_source_t *png_ptr,
    grim_png_info_source_t *info_ptr,
    png_bytep trans,
    int num_trans,
    png_color_16p trans_values)
{
    if (png_ptr == NULL || info_ptr == NULL)
        return;

    if (trans != NULL)
        info_ptr->trans = trans;

    if (trans_values != NULL) {
        png_memcpy(
            &info_ptr->trans_values,
            trans_values,
            sizeof(png_color_16));
        if (num_trans == 0)
            num_trans = 1;
    }
    info_ptr->num_trans = (png_uint_16)num_trans;
    info_ptr->valid |= PNG_INFO_tRNS;
}

extern "C" png_voidp grim_png_create_struct(int type)
{
    png_size_t size;
    png_voidp struct_ptr;

    if (type == PNG_STRUCT_INFO)
        size = 0x40;
    else if (type == PNG_STRUCT_PNG)
        size = 0x19c;
    else
        return NULL;

    if ((struct_ptr = (png_voidp)malloc(size)) != NULL)
        png_memset(struct_ptr, 0, size);

    return struct_ptr;
}

extern "C" png_uint_32 grim_png_get_uint32(png_bytep buf)
{
    png_uint_32 value = ((png_uint_32)(*buf) << 24) +
        ((png_uint_32)(*(buf + 1)) << 16) +
        ((png_uint_32)(*(buf + 2)) << 8) +
        (png_uint_32)(*(buf + 3));

    return value;
}

extern "C" void grim_png_crc_read(
    grim_png_source_t *png_ptr, png_bytep buf, png_size_t length)
{
    png_read_data((png_structp)png_ptr, buf, length);
    png_calculate_crc((png_structp)png_ptr, buf, length);
}

extern "C" int grim_png_crc_error(grim_png_source_t *png_ptr)
{
    png_byte crc_bytes[4];
    png_uint_32 crc;
    int need_crc = 1;

    if (png_ptr->chunk_name[0] & 0x20) {
        if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_MASK) ==
            (PNG_FLAG_CRC_ANCILLARY_USE | PNG_FLAG_CRC_ANCILLARY_NOWARN))
            need_crc = 0;
    } else if (png_ptr->flags & PNG_FLAG_CRC_CRITICAL_IGNORE) {
        need_crc = 0;
    }

    png_read_data((png_structp)png_ptr, crc_bytes, 4);

    if (need_crc) {
        crc = png_get_uint_32(crc_bytes);
        return (int)(crc != png_ptr->crc);
    }
    return 0;
}

extern "C" void grim_png_check_chunk_name(
    grim_png_source_t *png_ptr, png_bytep chunk_name)
{
    if (chunk_name[0] < 41 || chunk_name[0] > 122 ||
        (chunk_name[0] > 90 && chunk_name[0] < 97) ||
        chunk_name[1] < 41 || chunk_name[1] > 122 ||
        (chunk_name[1] > 90 && chunk_name[1] < 97) ||
        chunk_name[2] < 41 || chunk_name[2] > 122 ||
        (chunk_name[2] > 90 && chunk_name[2] < 97) ||
        chunk_name[3] < 41 || chunk_name[3] > 122 ||
        (chunk_name[3] > 90 && chunk_name[3] < 97)) {
        png_chunk_error((png_structp)png_ptr, "invalid chunk type");
    }
}

extern "C" int grim_png_crc_finish(
    grim_png_source_t *png_ptr, png_uint_32 skip)
{
    png_size_t i;
    png_size_t istop = png_ptr->zbuf_size;

    for (i = (png_size_t)skip; i > istop; i -= istop)
        png_crc_read((png_structp)png_ptr, png_ptr->zbuf, png_ptr->zbuf_size);

    if (i)
        png_crc_read((png_structp)png_ptr, png_ptr->zbuf, i);

    if (png_crc_error((png_structp)png_ptr)) {
        if ((png_ptr->chunk_name[0] & 0x20 &&
             !(png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_NOWARN)) ||
            (!(png_ptr->chunk_name[0] & 0x20) &&
             png_ptr->flags & PNG_FLAG_CRC_CRITICAL_USE)) {
            png_chunk_warning((png_structp)png_ptr, "CRC error");
        } else {
            png_chunk_error((png_structp)png_ptr, "CRC error");
        }
        return 1;
    }

    return 0;
}

extern "C" void grim_png_handle_iend(
    grim_png_source_t *png_ptr,
    png_infop info_ptr,
    png_uint_32 length)
{
    if (!(png_ptr->mode & PNG_HAVE_IHDR) ||
        !(png_ptr->mode & PNG_HAVE_IDAT)) {
        png_error((png_structp)png_ptr, "No image in file");
        if (info_ptr == NULL)
            return;
    }

    png_ptr->mode |= PNG_AFTER_IDAT | PNG_HAVE_IEND;

    if (length != 0)
        png_warning((png_structp)png_ptr, "Incorrect IEND chunk length");
    png_crc_finish((png_structp)png_ptr, length);
}

extern "C" void grim_png_handle_unknown(
    grim_png_source_t *png_ptr,
    png_infop info_ptr,
    png_uint_32 length)
{
    png_check_chunk_name((png_structp)png_ptr, png_ptr->chunk_name);

    if (!(png_ptr->chunk_name[0] & 0x20)) {
        png_chunk_error((png_structp)png_ptr, "unknown critical chunk");
        if (info_ptr == NULL)
            return;
    }

    if (png_ptr->mode & PNG_HAVE_IDAT)
        png_ptr->mode |= PNG_AFTER_IDAT;

    png_crc_finish((png_structp)png_ptr, length);
}
