/*
 * Matcher-only adaptation of IJG libjpeg 6a jquant2.c.
 * Copyright (C) 1991-1996, Thomas G. Lane.
 *
 * The D3DX object uses byte-sized private booleans and a private decompressor
 * layout. Archive-backed fields are declared explicitly while the quantizer
 * algorithms retain the original IJG source shape.
 */

typedef struct grim_jpeg_common_quant2_source_s
    grim_jpeg_common_quant2_source_t;
typedef struct grim_jpeg_decompress_quant2_source_s
    grim_jpeg_decompress_quant2_source_t;

typedef void *(__cdecl *grim_jpeg_alloc_small_quant2_source_fn_t)(
    grim_jpeg_common_quant2_source_t *, int, unsigned int);
typedef void *(__cdecl *grim_jpeg_alloc_large_quant2_source_fn_t)(
    grim_jpeg_common_quant2_source_t *, int, unsigned int);
typedef unsigned char **(__cdecl *grim_jpeg_alloc_sarray_quant2_source_fn_t)(
    grim_jpeg_common_quant2_source_t *, int, unsigned int, unsigned int);

typedef struct grim_jpeg_memory_quant2_source_s {
    grim_jpeg_alloc_small_quant2_source_fn_t alloc_small;
    grim_jpeg_alloc_large_quant2_source_fn_t alloc_large;
    grim_jpeg_alloc_sarray_quant2_source_fn_t alloc_sarray;
} grim_jpeg_memory_quant2_source_t;

typedef void (__cdecl *grim_jpeg_error_exit_quant2_source_fn_t)(
    grim_jpeg_common_quant2_source_t *);
typedef void (__cdecl *grim_jpeg_emit_message_quant2_source_fn_t)(
    grim_jpeg_common_quant2_source_t *, int);

typedef struct grim_jpeg_error_quant2_source_s {
    grim_jpeg_error_exit_quant2_source_fn_t error_exit;
    grim_jpeg_emit_message_quant2_source_fn_t emit_message;
    void *output_message;
    void *format_message;
    void *reset_error_manager;
    int message_code;
    int message_parameters[20];
} grim_jpeg_error_quant2_source_t;

typedef void (__cdecl *grim_jpeg_start_quant2_source_fn_t)(
    grim_jpeg_decompress_quant2_source_t *, unsigned char);
typedef void (__cdecl *grim_jpeg_color_quantize2_source_fn_t)(
    grim_jpeg_decompress_quant2_source_t *,
    unsigned char **,
    unsigned char **,
    int);
typedef void (__cdecl *grim_jpeg_finish_quant2_source_fn_t)(
    grim_jpeg_decompress_quant2_source_t *);

typedef unsigned short grim_jpeg_hist1d_quant2_source_t[32];
typedef grim_jpeg_hist1d_quant2_source_t *grim_jpeg_hist2d_quant2_source_t;
typedef grim_jpeg_hist2d_quant2_source_t *grim_jpeg_hist3d_quant2_source_t;

typedef struct grim_jpeg_color_quantizer_quant2_source_s {
    grim_jpeg_start_quant2_source_fn_t start_pass;
    grim_jpeg_color_quantize2_source_fn_t color_quantize;
    grim_jpeg_finish_quant2_source_fn_t finish_pass;
    grim_jpeg_finish_quant2_source_fn_t new_color_map;
    unsigned char **saved_colormap;
    int desired_color_count;
    grim_jpeg_hist3d_quant2_source_t histogram;
    unsigned char needs_zeroed;
    unsigned char fields_1d[3];
    short *fs_errors;
    unsigned char on_odd_row;
    unsigned char fields_25[3];
    int *error_limiter;
} grim_jpeg_color_quantizer_quant2_source_t;

struct grim_jpeg_common_quant2_source_s {
    grim_jpeg_error_quant2_source_t *error;
    grim_jpeg_memory_quant2_source_t *memory;
    void *progress;
    unsigned char fields_0c[4];
    int global_state;
};

struct grim_jpeg_decompress_quant2_source_s {
    grim_jpeg_error_quant2_source_t *error;
    grim_jpeg_memory_quant2_source_t *memory;
    void *progress;
    unsigned char fields_0c[0x40];
    int dither_mode;
    unsigned char fields_50[4];
    int desired_number_of_colors;
    unsigned char fields_58[2];
    unsigned char enable_two_pass_quantization;
    unsigned char fields_5b[1];
    unsigned int output_width;
    unsigned int output_height;
    int output_color_components;
    unsigned char fields_68[8];
    int actual_number_of_colors;
    unsigned char **colormap;
    unsigned char fields_78[0xa4];
    unsigned char *sample_range_limit;
    unsigned char fields_120[0x84];
    grim_jpeg_color_quantizer_quant2_source_t *color_quantizer;
};

typedef struct grim_jpeg_color_box_quant2_source_s {
    int c0_min;
    int c0_max;
    int c1_min;
    int c1_max;
    int c2_min;
    int c2_max;
    long volume;
    long color_count;
} grim_jpeg_color_box_quant2_source_t;

void __cdecl grim_jpeg_zero_far(void *, unsigned int);
static void grim_jpeg_pass2_no_dither(
    grim_jpeg_decompress_quant2_source_t *,
    unsigned char **,
    unsigned char **,
    int);
static void grim_jpeg_pass2_fs_dither(
    grim_jpeg_decompress_quant2_source_t *,
    unsigned char **,
    unsigned char **,
    int);

static void grim_jpeg_prescan_quantize(
    grim_jpeg_decompress_quant2_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    register unsigned char *input_pointer;
    register unsigned short *histogram_pointer;
    register grim_jpeg_hist3d_quant2_source_t histogram =
        quantizer->histogram;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;

    for (row = 0; row < row_count; row++) {
        input_pointer = input_buffer[row];
        for (column = width; column > 0; column--) {
            histogram_pointer =
                &histogram[input_pointer[0] >> 3]
                          [input_pointer[1] >> 2]
                          [input_pointer[2] >> 3];
            if (++(*histogram_pointer) <= 0)
                (*histogram_pointer)--;
            input_pointer += 3;
        }
    }
}

static grim_jpeg_color_box_quant2_source_t *
grim_jpeg_find_biggest_color_population(
    grim_jpeg_color_box_quant2_source_t *boxes, int box_count)
{
    register grim_jpeg_color_box_quant2_source_t *box;
    register int index;
    register long maximum = 0;
    grim_jpeg_color_box_quant2_source_t *which = 0;

    for (index = 0, box = boxes; index < box_count; index++, box++) {
        if (box->color_count > maximum && box->volume > 0) {
            which = box;
            maximum = box->color_count;
        }
    }
    return which;
}

static grim_jpeg_color_box_quant2_source_t *grim_jpeg_find_biggest_volume(
    grim_jpeg_color_box_quant2_source_t *boxes, int box_count)
{
    register grim_jpeg_color_box_quant2_source_t *box;
    register int index;
    register long maximum = 0;
    grim_jpeg_color_box_quant2_source_t *which = 0;

    for (index = 0, box = boxes; index < box_count; index++, box++) {
        if (box->volume > maximum) {
            which = box;
            maximum = box->volume;
        }
    }
    return which;
}

static void grim_jpeg_update_color_box(
    grim_jpeg_decompress_quant2_source_t *decoder,
    grim_jpeg_color_box_quant2_source_t *box)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    unsigned short *histogram_pointer;
    int c0, c1, c2;
    int c0_min, c0_max, c1_min, c1_max, c2_min, c2_max;
    long distance0, distance1, distance2;
    long color_count;

    c0_min = box->c0_min;
    c0_max = box->c0_max;
    c1_min = box->c1_min;
    c1_max = box->c1_max;
    c2_min = box->c2_min;
    c2_max = box->c2_max;

    if (c0_max > c0_min)
        for (c0 = c0_min; c0 <= c0_max; c0++)
            for (c1 = c1_min; c1 <= c1_max; c1++) {
                histogram_pointer = &histogram[c0][c1][c2_min];
                for (c2 = c2_min; c2 <= c2_max; c2++)
                    if (*histogram_pointer++ != 0) {
                        box->c0_min = c0_min = c0;
                        goto have_c0_min;
                    }
            }
have_c0_min:
    if (c0_max > c0_min)
        for (c0 = c0_max; c0 >= c0_min; c0--)
            for (c1 = c1_min; c1 <= c1_max; c1++) {
                histogram_pointer = &histogram[c0][c1][c2_min];
                for (c2 = c2_min; c2 <= c2_max; c2++)
                    if (*histogram_pointer++ != 0) {
                        box->c0_max = c0_max = c0;
                        goto have_c0_max;
                    }
            }
have_c0_max:
    if (c1_max > c1_min)
        for (c1 = c1_min; c1 <= c1_max; c1++)
            for (c0 = c0_min; c0 <= c0_max; c0++) {
                histogram_pointer = &histogram[c0][c1][c2_min];
                for (c2 = c2_min; c2 <= c2_max; c2++)
                    if (*histogram_pointer++ != 0) {
                        box->c1_min = c1_min = c1;
                        goto have_c1_min;
                    }
            }
have_c1_min:
    if (c1_max > c1_min)
        for (c1 = c1_max; c1 >= c1_min; c1--)
            for (c0 = c0_min; c0 <= c0_max; c0++) {
                histogram_pointer = &histogram[c0][c1][c2_min];
                for (c2 = c2_min; c2 <= c2_max; c2++)
                    if (*histogram_pointer++ != 0) {
                        box->c1_max = c1_max = c1;
                        goto have_c1_max;
                    }
            }
have_c1_max:
    if (c2_max > c2_min)
        for (c2 = c2_min; c2 <= c2_max; c2++)
            for (c0 = c0_min; c0 <= c0_max; c0++) {
                histogram_pointer = &histogram[c0][c1_min][c2];
                for (c1 = c1_min;
                     c1 <= c1_max;
                     c1++, histogram_pointer += 32)
                    if (*histogram_pointer != 0) {
                        box->c2_min = c2_min = c2;
                        goto have_c2_min;
                    }
            }
have_c2_min:
    if (c2_max > c2_min)
        for (c2 = c2_max; c2 >= c2_min; c2--)
            for (c0 = c0_min; c0 <= c0_max; c0++) {
                histogram_pointer = &histogram[c0][c1_min][c2];
                for (c1 = c1_min;
                     c1 <= c1_max;
                     c1++, histogram_pointer += 32)
                    if (*histogram_pointer != 0) {
                        box->c2_max = c2_max = c2;
                        goto have_c2_max;
                    }
            }
have_c2_max:
    distance0 = ((c0_max - c0_min) << 3) * 2;
    distance1 = ((c1_max - c1_min) << 2) * 3;
    distance2 = (c2_max - c2_min) << 3;
    box->volume = distance0 * distance0 +
                  distance1 * distance1 +
                  distance2 * distance2;

    color_count = 0;
    for (c0 = c0_min; c0 <= c0_max; c0++)
        for (c1 = c1_min; c1 <= c1_max; c1++) {
            histogram_pointer = &histogram[c0][c1][c2_min];
            for (c2 = c2_min;
                 c2 <= c2_max;
                 c2++, histogram_pointer++)
                if (*histogram_pointer != 0)
                    color_count++;
        }
    box->color_count = color_count;
}

static int grim_jpeg_median_cut(
    grim_jpeg_decompress_quant2_source_t *decoder,
    grim_jpeg_color_box_quant2_source_t *boxes,
    int box_count,
    int desired_color_count)
{
    int axis, lower_bound;
    int c0, c1, c2, maximum;
    register grim_jpeg_color_box_quant2_source_t *box1, *box2;

    while (box_count < desired_color_count) {
        if (box_count * 2 <= desired_color_count)
            box1 = grim_jpeg_find_biggest_color_population(boxes, box_count);
        else
            box1 = grim_jpeg_find_biggest_volume(boxes, box_count);
        if (box1 == 0)
            break;
        box2 = &boxes[box_count];
        box2->c0_max = box1->c0_max;
        box2->c1_max = box1->c1_max;
        box2->c2_max = box1->c2_max;
        box2->c0_min = box1->c0_min;
        box2->c1_min = box1->c1_min;
        box2->c2_min = box1->c2_min;

        c0 = ((box1->c0_max - box1->c0_min) << 3) * 2;
        c1 = ((box1->c1_max - box1->c1_min) << 2) * 3;
        c2 = (box1->c2_max - box1->c2_min) << 3;
        maximum = c1;
        axis = 1;
        if (c0 > maximum) {
            maximum = c0;
            axis = 0;
        }
        if (c2 > maximum)
            axis = 2;

        switch (axis) {
        case 0:
            lower_bound = (box1->c0_max + box1->c0_min) / 2;
            box1->c0_max = lower_bound;
            box2->c0_min = lower_bound + 1;
            break;
        case 1:
            lower_bound = (box1->c1_max + box1->c1_min) / 2;
            box1->c1_max = lower_bound;
            box2->c1_min = lower_bound + 1;
            break;
        case 2:
            lower_bound = (box1->c2_max + box1->c2_min) / 2;
            box1->c2_max = lower_bound;
            box2->c2_min = lower_bound + 1;
            break;
        }
        grim_jpeg_update_color_box(decoder, box1);
        grim_jpeg_update_color_box(decoder, box2);
        box_count++;
    }
    return box_count;
}

static void grim_jpeg_compute_color(
    grim_jpeg_decompress_quant2_source_t *decoder,
    grim_jpeg_color_box_quant2_source_t *box,
    int color_index)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    unsigned short *histogram_pointer;
    int c0, c1, c2;
    int c0_min, c0_max, c1_min, c1_max, c2_min, c2_max;
    long count;
    long total = 0;
    long c0_total = 0;
    long c1_total = 0;
    long c2_total = 0;

    c0_min = box->c0_min;
    c0_max = box->c0_max;
    c1_min = box->c1_min;
    c1_max = box->c1_max;
    c2_min = box->c2_min;
    c2_max = box->c2_max;

    for (c0 = c0_min; c0 <= c0_max; c0++)
        for (c1 = c1_min; c1 <= c1_max; c1++) {
            histogram_pointer = &histogram[c0][c1][c2_min];
            for (c2 = c2_min; c2 <= c2_max; c2++) {
                if ((count = *histogram_pointer++) != 0) {
                    total += count;
                    c0_total += ((c0 << 3) + 4) * count;
                    c1_total += ((c1 << 2) + 2) * count;
                    c2_total += ((c2 << 3) + 4) * count;
                }
            }
        }

    decoder->colormap[0][color_index] =
        (unsigned char)((c0_total + (total >> 1)) / total);
    decoder->colormap[1][color_index] =
        (unsigned char)((c1_total + (total >> 1)) / total);
    decoder->colormap[2][color_index] =
        (unsigned char)((c2_total + (total >> 1)) / total);
}

static void grim_jpeg_select_colors(
    grim_jpeg_decompress_quant2_source_t *decoder, int desired_color_count)
{
    grim_jpeg_color_box_quant2_source_t *boxes;
    int box_count;
    int index;

    boxes = (grim_jpeg_color_box_quant2_source_t *)
        decoder->memory->alloc_small(
            (grim_jpeg_common_quant2_source_t *)decoder,
            1,
            desired_color_count * sizeof(grim_jpeg_color_box_quant2_source_t));
    box_count = 1;
    boxes[0].c0_min = 0;
    boxes[0].c0_max = 31;
    boxes[0].c1_min = 0;
    boxes[0].c1_max = 63;
    boxes[0].c2_min = 0;
    boxes[0].c2_max = 31;
    grim_jpeg_update_color_box(decoder, &boxes[0]);
    box_count = grim_jpeg_median_cut(
        decoder, boxes, box_count, desired_color_count);
    for (index = 0; index < box_count; index++)
        grim_jpeg_compute_color(decoder, &boxes[index], index);
    decoder->actual_number_of_colors = box_count;
    decoder->error->message_code = 95;
    decoder->error->message_parameters[0] = box_count;
    decoder->error->emit_message(
        (grim_jpeg_common_quant2_source_t *)decoder, 1);
}

static int grim_jpeg_find_nearby_colors(
    grim_jpeg_decompress_quant2_source_t *decoder,
    int minimum_c0,
    int minimum_c1,
    int minimum_c2,
    unsigned char color_list[256])
{
    int color_count = decoder->actual_number_of_colors;
    int maximum_c0, maximum_c1, maximum_c2;
    int center_c0, center_c1, center_c2;
    int index, value, nearby_count;
    long minimum_maximum_distance;
    long minimum_distance, maximum_distance, distance;
    long minimum_distances[256];

    maximum_c0 = minimum_c0 + 24;
    center_c0 = (minimum_c0 + maximum_c0) >> 1;
    maximum_c1 = minimum_c1 + 28;
    center_c1 = (minimum_c1 + maximum_c1) >> 1;
    maximum_c2 = minimum_c2 + 24;
    center_c2 = (minimum_c2 + maximum_c2) >> 1;

    minimum_maximum_distance = 0x7fffffffL;

    for (index = 0; index < color_count; index++) {
        value = decoder->colormap[0][index];
        if (value < minimum_c0) {
            distance = (value - minimum_c0) * 2;
            minimum_distance = distance * distance;
            distance = (value - maximum_c0) * 2;
            maximum_distance = distance * distance;
        } else if (value > maximum_c0) {
            distance = (value - maximum_c0) * 2;
            minimum_distance = distance * distance;
            distance = (value - minimum_c0) * 2;
            maximum_distance = distance * distance;
        } else {
            minimum_distance = 0;
            if (value <= center_c0) {
                distance = (value - maximum_c0) * 2;
                maximum_distance = distance * distance;
            } else {
                distance = (value - minimum_c0) * 2;
                maximum_distance = distance * distance;
            }
        }

        value = decoder->colormap[1][index];
        if (value < minimum_c1) {
            distance = (value - minimum_c1) * 3;
            minimum_distance += distance * distance;
            distance = (value - maximum_c1) * 3;
            maximum_distance += distance * distance;
        } else if (value > maximum_c1) {
            distance = (value - maximum_c1) * 3;
            minimum_distance += distance * distance;
            distance = (value - minimum_c1) * 3;
            maximum_distance += distance * distance;
        } else {
            if (value <= center_c1) {
                distance = (value - maximum_c1) * 3;
                maximum_distance += distance * distance;
            } else {
                distance = (value - minimum_c1) * 3;
                maximum_distance += distance * distance;
            }
        }

        value = decoder->colormap[2][index];
        if (value < minimum_c2) {
            distance = value - minimum_c2;
            minimum_distance += distance * distance;
            distance = value - maximum_c2;
            maximum_distance += distance * distance;
        } else if (value > maximum_c2) {
            distance = value - maximum_c2;
            minimum_distance += distance * distance;
            distance = value - minimum_c2;
            maximum_distance += distance * distance;
        } else {
            if (value <= center_c2) {
                distance = value - maximum_c2;
                maximum_distance += distance * distance;
            } else {
                distance = value - minimum_c2;
                maximum_distance += distance * distance;
            }
        }

        minimum_distances[index] = minimum_distance;
        if (maximum_distance < minimum_maximum_distance)
            minimum_maximum_distance = maximum_distance;
    }

    nearby_count = 0;
    for (index = 0; index < color_count; index++) {
        if (minimum_distances[index] <= minimum_maximum_distance)
            color_list[nearby_count++] = (unsigned char)index;
    }
    return nearby_count;
}

static void grim_jpeg_find_best_colors(
    grim_jpeg_decompress_quant2_source_t *decoder,
    int minimum_c0,
    int minimum_c1,
    int minimum_c2,
    int color_count,
    unsigned char color_list[256],
    unsigned char best_color[128])
{
    int c0_index, c1_index, c2_index;
    int index, color_index;
    register long *best_distance_pointer;
    unsigned char *color_pointer;
    long distance0, distance1;
    register long distance2;
    long difference0, difference1;
    register long difference2;
    long increment0, increment1, increment2;
    long best_distances[128];

    best_distance_pointer = best_distances;
    for (index = 127; index >= 0; index--)
        *best_distance_pointer++ = 0x7fffffffL;

    for (index = 0; index < color_count; index++) {
        color_index = color_list[index];
        increment0 =
            (minimum_c0 - decoder->colormap[0][color_index]) * 2;
        distance0 = increment0 * increment0;
        increment1 =
            (minimum_c1 - decoder->colormap[1][color_index]) * 3;
        distance0 += increment1 * increment1;
        increment2 = minimum_c2 - decoder->colormap[2][color_index];
        distance0 += increment2 * increment2;
        increment0 = increment0 * 32 + 256;
        increment1 = increment1 * 24 + 144;
        increment2 = increment2 * 16 + 64;

        best_distance_pointer = best_distances;
        color_pointer = best_color;
        difference0 = increment0;
        for (c0_index = 3; c0_index >= 0; c0_index--) {
            distance1 = distance0;
            difference1 = increment1;
            for (c1_index = 7; c1_index >= 0; c1_index--) {
                distance2 = distance1;
                difference2 = increment2;
                for (c2_index = 3; c2_index >= 0; c2_index--) {
                    if (distance2 < *best_distance_pointer) {
                        *best_distance_pointer = distance2;
                        *color_pointer = (unsigned char)color_index;
                    }
                    distance2 += difference2;
                    difference2 += 128;
                    best_distance_pointer++;
                    color_pointer++;
                }
                distance1 += difference1;
                difference1 += 288;
            }
            distance0 += difference0;
            difference0 += 512;
        }
    }
}

static void grim_jpeg_fill_inverse_cmap(
    grim_jpeg_decompress_quant2_source_t *decoder,
    int c0,
    int c1,
    int c2)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    int minimum_c0, minimum_c1, minimum_c2;
    int c0_index, c1_index, c2_index;
    register unsigned char *color_pointer;
    register unsigned short *cache_pointer;
    unsigned char color_list[256];
    int color_count;
    unsigned char best_color[128];

    c0 >>= 2;
    c1 >>= 3;
    c2 >>= 2;

    minimum_c0 = (c0 << 5) + 4;
    minimum_c1 = (c1 << 5) + 2;
    minimum_c2 = (c2 << 5) + 4;

    color_count = grim_jpeg_find_nearby_colors(
        decoder, minimum_c0, minimum_c1, minimum_c2, color_list);
    grim_jpeg_find_best_colors(
        decoder,
        minimum_c0,
        minimum_c1,
        minimum_c2,
        color_count,
        color_list,
        best_color);

    c0 <<= 2;
    c1 <<= 3;
    c2 <<= 2;
    color_pointer = best_color;
    for (c0_index = 0; c0_index < 4; c0_index++) {
        for (c1_index = 0; c1_index < 8; c1_index++) {
            cache_pointer = &histogram[c0 + c0_index][c1 + c1_index][c2];
            for (c2_index = 0; c2_index < 4; c2_index++)
                *cache_pointer++ = (unsigned short)(*color_pointer++ + 1);
        }
    }
}

static void grim_jpeg_pass2_no_dither(
    grim_jpeg_decompress_quant2_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    register unsigned char *input_pointer, *output_pointer;
    register unsigned short *cache_pointer;
    register int c0, c1, c2;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;

    for (row = 0; row < row_count; row++) {
        input_pointer = input_buffer[row];
        output_pointer = output_buffer[row];
        for (column = width; column > 0; column--) {
            c0 = *input_pointer++ >> 3;
            c1 = *input_pointer++ >> 2;
            c2 = *input_pointer++ >> 3;
            cache_pointer = &histogram[c0][c1][c2];
            if (*cache_pointer == 0)
                grim_jpeg_fill_inverse_cmap(decoder, c0, c1, c2);
            *output_pointer++ = (unsigned char)(*cache_pointer - 1);
        }
    }
}

static void grim_jpeg_pass2_fs_dither(
    grim_jpeg_decompress_quant2_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    register int current0, current1, current2;
    int below_error0, below_error1, below_error2;
    int previous_below_error0, previous_below_error1, previous_below_error2;
    register short *error_pointer;
    unsigned char *input_pointer;
    unsigned char *output_pointer;
    unsigned short *cache_pointer;
    int direction;
    int direction3;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;
    unsigned char *range_limit = decoder->sample_range_limit;
    int *error_limit = quantizer->error_limiter;
    unsigned char *colormap0 = decoder->colormap[0];
    unsigned char *colormap1 = decoder->colormap[1];
    unsigned char *colormap2 = decoder->colormap[2];

    for (row = 0; row < row_count; row++) {
        input_pointer = input_buffer[row];
        output_pointer = output_buffer[row];
        if (quantizer->on_odd_row) {
            input_pointer += (width - 1) * 3;
            output_pointer += width - 1;
            direction = -1;
            direction3 = -3;
            error_pointer = quantizer->fs_errors + (width + 1) * 3;
            quantizer->on_odd_row = 0;
        } else {
            direction = 1;
            direction3 = 3;
            error_pointer = quantizer->fs_errors;
            quantizer->on_odd_row = 1;
        }
        current0 = current1 = current2 = 0;
        below_error0 = below_error1 = below_error2 = 0;
        previous_below_error0 = previous_below_error1 =
            previous_below_error2 = 0;

        for (column = width; column > 0; column--) {
            current0 = (current0 + error_pointer[direction3] + 8) >> 4;
            current1 = (current1 + error_pointer[direction3 + 1] + 8) >> 4;
            current2 = (current2 + error_pointer[direction3 + 2] + 8) >> 4;
            current0 = error_limit[current0];
            current1 = error_limit[current1];
            current2 = error_limit[current2];
            current0 += input_pointer[0];
            current1 += input_pointer[1];
            current2 += input_pointer[2];
            current0 = range_limit[current0];
            current1 = range_limit[current1];
            current2 = range_limit[current2];
            cache_pointer =
                &histogram[current0 >> 3][current1 >> 2][current2 >> 3];
            if (*cache_pointer == 0)
                grim_jpeg_fill_inverse_cmap(
                    decoder, current0 >> 3, current1 >> 2, current2 >> 3);
            {
                register int pixel_code = *cache_pointer - 1;
                *output_pointer = (unsigned char)pixel_code;
                current0 -= colormap0[pixel_code];
                current1 -= colormap1[pixel_code];
                current2 -= colormap2[pixel_code];
            }
            {
                register int next_below_error, delta;

                next_below_error = current0;
                delta = current0 * 2;
                current0 += delta;
                error_pointer[0] = (short)(previous_below_error0 + current0);
                current0 += delta;
                previous_below_error0 = below_error0 + current0;
                below_error0 = next_below_error;
                current0 += delta;

                next_below_error = current1;
                delta = current1 * 2;
                current1 += delta;
                error_pointer[1] = (short)(previous_below_error1 + current1);
                current1 += delta;
                previous_below_error1 = below_error1 + current1;
                below_error1 = next_below_error;
                current1 += delta;

                next_below_error = current2;
                delta = current2 * 2;
                current2 += delta;
                error_pointer[2] = (short)(previous_below_error2 + current2);
                current2 += delta;
                previous_below_error2 = below_error2 + current2;
                below_error2 = next_below_error;
                current2 += delta;
            }
            input_pointer += direction3;
            output_pointer += direction;
            error_pointer += direction3;
        }
        error_pointer[0] = (short)previous_below_error0;
        error_pointer[1] = (short)previous_below_error1;
        error_pointer[2] = (short)previous_below_error2;
    }
}

static void grim_jpeg_init_error_limit(
    grim_jpeg_decompress_quant2_source_t *decoder)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    int *table;
    int input, output;

    table = (int *)decoder->memory->alloc_small(
        (grim_jpeg_common_quant2_source_t *)decoder,
        1,
        511 * sizeof(int));
    table += 255;
    quantizer->error_limiter = table;

    output = 0;
    for (input = 0; input < 16; input++, output++) {
        table[input] = output;
        table[-input] = -output;
    }
    for (; input < 48; input++, output += (input & 1) ? 0 : 1) {
        table[input] = output;
        table[-input] = -output;
    }
    for (; input <= 255; input++) {
        table[input] = output;
        table[-input] = -output;
    }
}

static void grim_jpeg_finish_pass_one_quant2(
    grim_jpeg_decompress_quant2_source_t *decoder)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;

    decoder->colormap = quantizer->saved_colormap;
    grim_jpeg_select_colors(decoder, quantizer->desired_color_count);
    quantizer->needs_zeroed = 1;
}

static void grim_jpeg_finish_pass_two_quant2(
    grim_jpeg_decompress_quant2_source_t *decoder)
{
}

static void grim_jpeg_start_pass_two_quantizer(
    grim_jpeg_decompress_quant2_source_t *decoder, unsigned char is_prescan)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer =
        decoder->color_quantizer;
    grim_jpeg_hist3d_quant2_source_t histogram = quantizer->histogram;
    int index;

    if (decoder->dither_mode != 0)
        decoder->dither_mode = 2;

    if (is_prescan) {
        quantizer->color_quantize = grim_jpeg_prescan_quantize;
        quantizer->finish_pass = grim_jpeg_finish_pass_one_quant2;
        quantizer->needs_zeroed = 1;
    } else {
        if (decoder->dither_mode == 2)
            quantizer->color_quantize = grim_jpeg_pass2_fs_dither;
        else
            quantizer->color_quantize = grim_jpeg_pass2_no_dither;
        quantizer->finish_pass = grim_jpeg_finish_pass_two_quant2;

        index = decoder->actual_number_of_colors;
        if (index < 1) {
            decoder->error->message_code = 55;
            decoder->error->message_parameters[0] = 1;
            decoder->error->error_exit(
                (grim_jpeg_common_quant2_source_t *)decoder);
        }
        if (index > 256) {
            decoder->error->message_code = 56;
            decoder->error->message_parameters[0] = 256;
            decoder->error->error_exit(
                (grim_jpeg_common_quant2_source_t *)decoder);
        }

        if (decoder->dither_mode == 2) {
            unsigned int array_size = (decoder->output_width + 2) * 6;
            if (quantizer->fs_errors == 0)
                quantizer->fs_errors = (short *)
                    decoder->memory->alloc_large(
                        (grim_jpeg_common_quant2_source_t *)decoder,
                        1,
                        array_size);
            grim_jpeg_zero_far(quantizer->fs_errors, array_size);
            if (quantizer->error_limiter == 0)
                grim_jpeg_init_error_limit(decoder);
            quantizer->on_odd_row = 0;
        }
    }

    if (quantizer->needs_zeroed) {
        for (index = 0; index < 32; index++)
            grim_jpeg_zero_far(histogram[index], 4096);
        quantizer->needs_zeroed = 0;
    }
}

static void grim_jpeg_new_color_map_two_quantizer(
    grim_jpeg_decompress_quant2_source_t *decoder)
{
    decoder->color_quantizer->needs_zeroed = 1;
}

void grim_jpeg_init_two_pass_quantizer(
    grim_jpeg_decompress_quant2_source_t *decoder)
{
    grim_jpeg_color_quantizer_quant2_source_t *quantizer;
    int index;

    quantizer = (grim_jpeg_color_quantizer_quant2_source_t *)
        decoder->memory->alloc_small(
            (grim_jpeg_common_quant2_source_t *)decoder,
            1,
            sizeof(grim_jpeg_color_quantizer_quant2_source_t));
    decoder->color_quantizer = quantizer;
    quantizer->start_pass = grim_jpeg_start_pass_two_quantizer;
    quantizer->new_color_map = grim_jpeg_new_color_map_two_quantizer;
    quantizer->fs_errors = 0;
    quantizer->error_limiter = 0;

    if (decoder->output_color_components != 3) {
        decoder->error->message_code = 46;
        decoder->error->error_exit(
            (grim_jpeg_common_quant2_source_t *)decoder);
    }

    quantizer->histogram = (grim_jpeg_hist3d_quant2_source_t)
        decoder->memory->alloc_small(
            (grim_jpeg_common_quant2_source_t *)decoder, 1, 128);
    for (index = 0; index < 32; index++) {
        quantizer->histogram[index] = (grim_jpeg_hist2d_quant2_source_t)
            decoder->memory->alloc_large(
                (grim_jpeg_common_quant2_source_t *)decoder, 1, 4096);
    }
    quantizer->needs_zeroed = 1;

    if (decoder->enable_two_pass_quantization) {
        int desired = decoder->desired_number_of_colors;
        if (desired < 8) {
            decoder->error->message_code = 55;
            decoder->error->message_parameters[0] = 8;
            decoder->error->error_exit(
                (grim_jpeg_common_quant2_source_t *)decoder);
        }
        if (desired > 256) {
            decoder->error->message_code = 56;
            decoder->error->message_parameters[0] = 256;
            decoder->error->error_exit(
                (grim_jpeg_common_quant2_source_t *)decoder);
        }
        quantizer->saved_colormap = decoder->memory->alloc_sarray(
            (grim_jpeg_common_quant2_source_t *)decoder,
            1,
            (unsigned int)desired,
            3);
        quantizer->desired_color_count = desired;
    } else {
        quantizer->saved_colormap = 0;
    }

    if (decoder->dither_mode != 0)
        decoder->dither_mode = 2;

    if (decoder->dither_mode == 2) {
        quantizer->fs_errors = (short *)decoder->memory->alloc_large(
            (grim_jpeg_common_quant2_source_t *)decoder,
            1,
            (decoder->output_width + 2) * 6);
        grim_jpeg_init_error_limit(decoder);
    }
}
