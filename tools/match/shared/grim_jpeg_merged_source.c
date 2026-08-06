/*
 * Matcher-only adaptation of IJG libjpeg 6a jdmerge.c.
 * Copyright (C) 1994-1996, Thomas G. Lane.
 *
 * This remains C source because the historical D3DX archive compiled the IJG
 * translation unit as C, which affects byte-sized boolean stores under MSVC 7.
 */

typedef struct grim_jpeg_common_merged_source_s
    grim_jpeg_common_merged_source_t;
typedef struct grim_jpeg_decompress_merged_source_s
    grim_jpeg_decompress_merged_source_t;

typedef void *(__cdecl *grim_jpeg_alloc_small_merged_source_fn_t)(
    grim_jpeg_common_merged_source_t *, int, unsigned int);
typedef void *(__cdecl *grim_jpeg_alloc_large_merged_source_fn_t)(
    grim_jpeg_common_merged_source_t *, int, unsigned int);

typedef struct grim_jpeg_memory_merged_source_s {
    grim_jpeg_alloc_small_merged_source_fn_t alloc_small;
    grim_jpeg_alloc_large_merged_source_fn_t alloc_large;
} grim_jpeg_memory_merged_source_t;

typedef void (__cdecl *grim_jpeg_merged_upmethod_source_fn_t)(
    grim_jpeg_decompress_merged_source_t *,
    unsigned char ***,
    unsigned int,
    unsigned char **);

typedef struct grim_jpeg_merged_upsampler_source_s {
    void *start_pass;
    void *upsample;
    unsigned char need_context_rows;
    unsigned char fields_09[3];
    grim_jpeg_merged_upmethod_source_fn_t upmethod;
    int *cr_r_table;
    int *cb_b_table;
    long *cr_g_table;
    long *cb_g_table;
    unsigned char *spare_row;
    unsigned char spare_full;
    unsigned char fields_25[3];
    unsigned int out_row_width;
    unsigned int rows_to_go;
} grim_jpeg_merged_upsampler_source_t;

struct grim_jpeg_common_merged_source_s {
    void *error;
    grim_jpeg_memory_merged_source_t *memory;
    void *progress;
    unsigned char fields_0c[4];
    int global_state;
};

struct grim_jpeg_decompress_merged_source_s {
    void *error;
    grim_jpeg_memory_merged_source_t *memory;
    void *progress;
    unsigned char fields_0c[0x50];
    unsigned int output_width;
    unsigned int output_height;
    int output_color_components;
    unsigned char fields_68[0xa8];
    int max_v_samp_factor;
    unsigned char fields_114[0x08];
    unsigned char *sample_range_limit;
    unsigned char fields_120[0x7c];
    grim_jpeg_merged_upsampler_source_t *upsampler;
};

void __cdecl grim_jpeg_copy_sample_rows(
    unsigned char **,
    int,
    unsigned char **,
    int,
    int,
    unsigned int);

#define GRIM_JPEG_MERGED_FIX(value) \
    ((long) ((value) * (1L << 16) + 0.5))

static void grim_jpeg_build_merged_ycc_rgb_table(
    grim_jpeg_decompress_merged_source_t *decoder)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;
    int index;
    long centered_sample;

    upsampler->cr_r_table = (int *) decoder->memory->alloc_small(
        (grim_jpeg_common_merged_source_t *) decoder,
        1,
        256 * sizeof(int));
    upsampler->cb_b_table = (int *) decoder->memory->alloc_small(
        (grim_jpeg_common_merged_source_t *) decoder,
        1,
        256 * sizeof(int));
    upsampler->cr_g_table = (long *) decoder->memory->alloc_small(
        (grim_jpeg_common_merged_source_t *) decoder,
        1,
        256 * sizeof(long));
    upsampler->cb_g_table = (long *) decoder->memory->alloc_small(
        (grim_jpeg_common_merged_source_t *) decoder,
        1,
        256 * sizeof(long));

    for (index = 0, centered_sample = -128;
         index <= 255;
         index++, centered_sample++) {
        upsampler->cr_r_table[index] = (int)
            ((GRIM_JPEG_MERGED_FIX(1.40200) * centered_sample +
              (1L << 15)) >> 16);
        upsampler->cb_b_table[index] = (int)
            ((GRIM_JPEG_MERGED_FIX(1.77200) * centered_sample +
              (1L << 15)) >> 16);
        upsampler->cr_g_table[index] =
            (-GRIM_JPEG_MERGED_FIX(0.71414)) * centered_sample;
        upsampler->cb_g_table[index] =
            (-GRIM_JPEG_MERGED_FIX(0.34414)) * centered_sample + (1L << 15);
    }
}

void grim_jpeg_start_pass_merged_upsample(
    grim_jpeg_decompress_merged_source_t *decoder)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;

    upsampler->spare_full = 0;
    upsampler->rows_to_go = decoder->output_height;
}

void grim_jpeg_merged_2v_upsample(
    grim_jpeg_decompress_merged_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int *input_row_group_counter,
    unsigned int input_row_groups_available,
    unsigned char **output_buffer,
    unsigned int *output_row_counter,
    unsigned int output_rows_available)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;
    unsigned char *work_rows[2];
    unsigned int row_count;

    if (upsampler->spare_full) {
        grim_jpeg_copy_sample_rows(
            &upsampler->spare_row,
            0,
            output_buffer + *output_row_counter,
            0,
            1,
            upsampler->out_row_width);
        row_count = 1;
        upsampler->spare_full = 0;
    } else {
        row_count = 2;
        if (row_count > upsampler->rows_to_go)
            row_count = upsampler->rows_to_go;
        output_rows_available -= *output_row_counter;
        if (row_count > output_rows_available)
            row_count = output_rows_available;
        work_rows[0] = output_buffer[*output_row_counter];
        if (row_count > 1) {
            work_rows[1] = output_buffer[*output_row_counter + 1];
        } else {
            work_rows[1] = upsampler->spare_row;
            upsampler->spare_full = 1;
        }
        upsampler->upmethod(
            decoder,
            input_buffer,
            *input_row_group_counter,
            work_rows);
    }

    *output_row_counter += row_count;
    upsampler->rows_to_go -= row_count;
    if (!upsampler->spare_full)
        (*input_row_group_counter)++;
}

void grim_jpeg_merged_1v_upsample(
    grim_jpeg_decompress_merged_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int *input_row_group_counter,
    unsigned int input_row_groups_available,
    unsigned char **output_buffer,
    unsigned int *output_row_counter,
    unsigned int output_rows_available)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;

    upsampler->upmethod(
        decoder,
        input_buffer,
        *input_row_group_counter,
        output_buffer + *output_row_counter);
    (*output_row_counter)++;
    (*input_row_group_counter)++;
}

void grim_jpeg_h2v1_merged_upsample(
    grim_jpeg_decompress_merged_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int input_row_group_counter,
    unsigned char **output_buffer)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;
    register int luminance, red, green, blue;
    int blue_chroma, red_chroma;
    register unsigned char *output_pointer;
    unsigned char *input_pointer_0;
    unsigned char *input_pointer_1;
    unsigned char *input_pointer_2;
    unsigned int column;
    register unsigned char *range_limit = decoder->sample_range_limit;
    int *cr_r_table = upsampler->cr_r_table;
    int *cb_b_table = upsampler->cb_b_table;
    long *cr_g_table = upsampler->cr_g_table;
    long *cb_g_table = upsampler->cb_g_table;

    input_pointer_0 = input_buffer[0][input_row_group_counter];
    input_pointer_1 = input_buffer[1][input_row_group_counter];
    input_pointer_2 = input_buffer[2][input_row_group_counter];
    output_pointer = output_buffer[0];
    for (column = decoder->output_width >> 1; column > 0; column--) {
        blue_chroma = *input_pointer_1++;
        red_chroma = *input_pointer_2++;
        red = cr_r_table[red_chroma];
        green = (int)
            ((cb_g_table[blue_chroma] + cr_g_table[red_chroma]) >> 16);
        blue = cb_b_table[blue_chroma];
        luminance = *input_pointer_0++;
        output_pointer[0] = range_limit[luminance + red];
        output_pointer[1] = range_limit[luminance + green];
        output_pointer[2] = range_limit[luminance + blue];
        output_pointer += 3;
        luminance = *input_pointer_0++;
        output_pointer[0] = range_limit[luminance + red];
        output_pointer[1] = range_limit[luminance + green];
        output_pointer[2] = range_limit[luminance + blue];
        output_pointer += 3;
    }
    if (decoder->output_width & 1) {
        blue_chroma = *input_pointer_1;
        red_chroma = *input_pointer_2;
        red = cr_r_table[red_chroma];
        green = (int)
            ((cb_g_table[blue_chroma] + cr_g_table[red_chroma]) >> 16);
        blue = cb_b_table[blue_chroma];
        luminance = *input_pointer_0;
        output_pointer[0] = range_limit[luminance + red];
        output_pointer[1] = range_limit[luminance + green];
        output_pointer[2] = range_limit[luminance + blue];
    }
}

void grim_jpeg_h2v2_merged_upsample(
    grim_jpeg_decompress_merged_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int input_row_group_counter,
    unsigned char **output_buffer)
{
    grim_jpeg_merged_upsampler_source_t *upsampler = decoder->upsampler;
    register int luminance, red, green, blue;
    int blue_chroma, red_chroma;
    register unsigned char *output_pointer_0;
    register unsigned char *output_pointer_1;
    unsigned char *input_pointer_00;
    unsigned char *input_pointer_01;
    unsigned char *input_pointer_1;
    unsigned char *input_pointer_2;
    unsigned int column;
    register unsigned char *range_limit = decoder->sample_range_limit;
    int *cr_r_table = upsampler->cr_r_table;
    int *cb_b_table = upsampler->cb_b_table;
    long *cr_g_table = upsampler->cr_g_table;
    long *cb_g_table = upsampler->cb_g_table;

    input_pointer_00 = input_buffer[0][input_row_group_counter * 2];
    input_pointer_01 = input_buffer[0][input_row_group_counter * 2 + 1];
    input_pointer_1 = input_buffer[1][input_row_group_counter];
    input_pointer_2 = input_buffer[2][input_row_group_counter];
    output_pointer_0 = output_buffer[0];
    output_pointer_1 = output_buffer[1];
    for (column = decoder->output_width >> 1; column > 0; column--) {
        blue_chroma = *input_pointer_1++;
        red_chroma = *input_pointer_2++;
        red = cr_r_table[red_chroma];
        green = (int)
            ((cb_g_table[blue_chroma] + cr_g_table[red_chroma]) >> 16);
        blue = cb_b_table[blue_chroma];
        luminance = *input_pointer_00++;
        output_pointer_0[0] = range_limit[luminance + red];
        output_pointer_0[1] = range_limit[luminance + green];
        output_pointer_0[2] = range_limit[luminance + blue];
        output_pointer_0 += 3;
        luminance = *input_pointer_00++;
        output_pointer_0[0] = range_limit[luminance + red];
        output_pointer_0[1] = range_limit[luminance + green];
        output_pointer_0[2] = range_limit[luminance + blue];
        output_pointer_0 += 3;
        luminance = *input_pointer_01++;
        output_pointer_1[0] = range_limit[luminance + red];
        output_pointer_1[1] = range_limit[luminance + green];
        output_pointer_1[2] = range_limit[luminance + blue];
        output_pointer_1 += 3;
        luminance = *input_pointer_01++;
        output_pointer_1[0] = range_limit[luminance + red];
        output_pointer_1[1] = range_limit[luminance + green];
        output_pointer_1[2] = range_limit[luminance + blue];
        output_pointer_1 += 3;
    }
    if (decoder->output_width & 1) {
        blue_chroma = *input_pointer_1;
        red_chroma = *input_pointer_2;
        red = cr_r_table[red_chroma];
        green = (int)
            ((cb_g_table[blue_chroma] + cr_g_table[red_chroma]) >> 16);
        blue = cb_b_table[blue_chroma];
        luminance = *input_pointer_00;
        output_pointer_0[0] = range_limit[luminance + red];
        output_pointer_0[1] = range_limit[luminance + green];
        output_pointer_0[2] = range_limit[luminance + blue];
        luminance = *input_pointer_01;
        output_pointer_1[0] = range_limit[luminance + red];
        output_pointer_1[1] = range_limit[luminance + green];
        output_pointer_1[2] = range_limit[luminance + blue];
    }
}

void grim_jpeg_init_merged_upsampler(
    grim_jpeg_decompress_merged_source_t *decoder)
{
    grim_jpeg_merged_upsampler_source_t *upsampler;

    upsampler = (grim_jpeg_merged_upsampler_source_t *)
        decoder->memory->alloc_small(
            (grim_jpeg_common_merged_source_t *) decoder,
            1,
            sizeof(grim_jpeg_merged_upsampler_source_t));
    decoder->upsampler = upsampler;
    upsampler->start_pass = grim_jpeg_start_pass_merged_upsample;
    upsampler->need_context_rows = 0;
    upsampler->out_row_width =
        decoder->output_width * decoder->output_color_components;

    if (decoder->max_v_samp_factor == 2) {
        upsampler->upsample = grim_jpeg_merged_2v_upsample;
        upsampler->upmethod = grim_jpeg_h2v2_merged_upsample;
        upsampler->spare_row = (unsigned char *)
            decoder->memory->alloc_large(
                (grim_jpeg_common_merged_source_t *) decoder,
                1,
                upsampler->out_row_width * sizeof(unsigned char));
    } else {
        upsampler->upsample = grim_jpeg_merged_1v_upsample;
        upsampler->upmethod = grim_jpeg_h2v1_merged_upsample;
        upsampler->spare_row = 0;
    }

    grim_jpeg_build_merged_ycc_rgb_table(decoder);
}

#undef GRIM_JPEG_MERGED_FIX
