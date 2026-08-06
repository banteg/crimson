/*
 * Matcher-only adaptation of IJG libjpeg 6a jquant1.c.
 * Copyright (C) 1991-1996, Thomas G. Lane.
 *
 * The D3DX build uses byte-sized JPEG booleans and a private decompressor
 * layout, so the archive-backed fields are declared explicitly here while
 * the quantization algorithms remain the original C source shape.
 */

typedef struct grim_jpeg_common_quant1_source_s
    grim_jpeg_common_quant1_source_t;
typedef struct grim_jpeg_decompress_quant1_source_s
    grim_jpeg_decompress_quant1_source_t;

typedef void *(__cdecl *grim_jpeg_alloc_small_quant1_source_fn_t)(
    grim_jpeg_common_quant1_source_t *, int, unsigned int);
typedef void *(__cdecl *grim_jpeg_alloc_large_quant1_source_fn_t)(
    grim_jpeg_common_quant1_source_t *, int, unsigned int);
typedef unsigned char **(__cdecl *grim_jpeg_alloc_sarray_quant1_source_fn_t)(
    grim_jpeg_common_quant1_source_t *, int, unsigned int, unsigned int);

typedef struct grim_jpeg_memory_quant1_source_s {
    grim_jpeg_alloc_small_quant1_source_fn_t alloc_small;
    grim_jpeg_alloc_large_quant1_source_fn_t alloc_large;
    grim_jpeg_alloc_sarray_quant1_source_fn_t alloc_sarray;
} grim_jpeg_memory_quant1_source_t;

typedef void (__cdecl *grim_jpeg_error_exit_quant1_source_fn_t)(
    grim_jpeg_common_quant1_source_t *);
typedef void (__cdecl *grim_jpeg_emit_message_quant1_source_fn_t)(
    grim_jpeg_common_quant1_source_t *, int);

typedef struct grim_jpeg_error_quant1_source_s {
    grim_jpeg_error_exit_quant1_source_fn_t error_exit;
    grim_jpeg_emit_message_quant1_source_fn_t emit_message;
    void *output_message;
    void *format_message;
    void *reset_error_manager;
    int message_code;
    int message_parameters[20];
} grim_jpeg_error_quant1_source_t;

typedef struct grim_jpeg_color_quantizer_source_s {
    void *start_pass;
    void *color_quantize;
    void *finish_pass;
    void *new_color_map;
    unsigned char **saved_colormap;
    int saved_actual_color_count;
    unsigned char **color_index;
    unsigned char is_padded;
    unsigned char fields_1d[3];
    int component_color_counts[4];
    int row_index;
    int (*ordered_dither[4])[16];
    short *fs_errors[4];
    unsigned char on_odd_row;
    unsigned char fields_55[3];
} grim_jpeg_color_quantizer_source_t;

struct grim_jpeg_common_quant1_source_s {
    grim_jpeg_error_quant1_source_t *error;
    grim_jpeg_memory_quant1_source_t *memory;
    void *progress;
    unsigned char fields_0c[4];
    int global_state;
};

struct grim_jpeg_decompress_quant1_source_s {
    grim_jpeg_error_quant1_source_t *error;
    grim_jpeg_memory_quant1_source_t *memory;
    void *progress;
    unsigned char fields_0c[0x1c];
    int output_color_space;
    unsigned char fields_2c[0x20];
    int dither_mode;
    unsigned char fields_50[0x04];
    int desired_number_of_colors;
    unsigned char fields_58[0x04];
    unsigned int output_width;
    unsigned int output_height;
    int output_color_components;
    unsigned char fields_68[0x08];
    int actual_number_of_colors;
    unsigned char **colormap;
    unsigned char fields_78[0xa4];
    unsigned char *sample_range_limit;
    unsigned char fields_120[0x84];
    grim_jpeg_color_quantizer_source_t *color_quantizer;
};

void __cdecl grim_jpeg_zero_far(void *, unsigned int);

static void grim_jpeg_color_quantize(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned char **color_index = quantizer->color_index;
    register int pixel_code, component_index;
    register unsigned char *input_pointer, *output_pointer;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;
    register int component_count = decoder->output_color_components;

    for (row = 0; row < row_count; row++) {
        input_pointer = input_buffer[row];
        output_pointer = output_buffer[row];
        for (column = width; column > 0; column--) {
            pixel_code = 0;
            for (component_index = 0;
                 component_index < component_count;
                 component_index++) {
                pixel_code += color_index[component_index][*input_pointer++];
            }
            *output_pointer++ = (unsigned char) pixel_code;
        }
    }
}

static void grim_jpeg_color_quantize3(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    register int pixel_code;
    register unsigned char *input_pointer, *output_pointer;
    unsigned char *color_index_0 = quantizer->color_index[0];
    unsigned char *color_index_1 = quantizer->color_index[1];
    unsigned char *color_index_2 = quantizer->color_index[2];
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;

    for (row = 0; row < row_count; row++) {
        input_pointer = input_buffer[row];
        output_pointer = output_buffer[row];
        for (column = width; column > 0; column--) {
            pixel_code = color_index_0[*input_pointer++];
            pixel_code += color_index_1[*input_pointer++];
            pixel_code += color_index_2[*input_pointer++];
            *output_pointer++ = (unsigned char) pixel_code;
        }
    }
}

static void grim_jpeg_quantize_ordered_dither(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    register unsigned char *input_pointer;
    register unsigned char *output_pointer;
    unsigned char *component_color_index;
    int *dither;
    int row_index, column_index;
    int component_count = decoder->output_color_components;
    int component_index;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;

    for (row = 0; row < row_count; row++) {
        grim_jpeg_zero_far(output_buffer[row], width * sizeof(unsigned char));
        row_index = quantizer->row_index;
        for (component_index = 0;
             component_index < component_count;
             component_index++) {
            input_pointer = input_buffer[row] + component_index;
            output_pointer = output_buffer[row];
            component_color_index = quantizer->color_index[component_index];
            dither = quantizer->ordered_dither[component_index][row_index];
            column_index = 0;

            for (column = width; column > 0; column--) {
                *output_pointer += component_color_index[
                    *input_pointer + dither[column_index]];
                input_pointer += component_count;
                output_pointer++;
                column_index = (column_index + 1) & 15;
            }
        }
        row_index = (row_index + 1) & 15;
        quantizer->row_index = row_index;
    }
}

static void grim_jpeg_quantize3_ordered_dither(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    register int pixel_code;
    register unsigned char *input_pointer;
    register unsigned char *output_pointer;
    unsigned char *color_index_0 = quantizer->color_index[0];
    unsigned char *color_index_1 = quantizer->color_index[1];
    unsigned char *color_index_2 = quantizer->color_index[2];
    int *dither_0;
    int *dither_1;
    int *dither_2;
    int row_index, column_index;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;

    for (row = 0; row < row_count; row++) {
        row_index = quantizer->row_index;
        input_pointer = input_buffer[row];
        output_pointer = output_buffer[row];
        dither_0 = quantizer->ordered_dither[0][row_index];
        dither_1 = quantizer->ordered_dither[1][row_index];
        dither_2 = quantizer->ordered_dither[2][row_index];
        column_index = 0;

        for (column = width; column > 0; column--) {
            pixel_code = color_index_0[*input_pointer++ + dither_0[column_index]];
            pixel_code += color_index_1[*input_pointer++ + dither_1[column_index]];
            pixel_code += color_index_2[*input_pointer++ + dither_2[column_index]];
            *output_pointer++ = (unsigned char) pixel_code;
            column_index = (column_index + 1) & 15;
        }
        row_index = (row_index + 1) & 15;
        quantizer->row_index = row_index;
    }
}

static void grim_jpeg_quantize_fs_dither(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char **input_buffer,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    register int current_error;
    int below_error;
    int below_previous_error;
    int below_next_error;
    int delta;
    register short *error_pointer;
    register unsigned char *input_pointer;
    register unsigned char *output_pointer;
    unsigned char *component_color_index;
    unsigned char *component_colormap;
    int pixel_code;
    int component_count = decoder->output_color_components;
    int direction;
    int component_direction;
    int component_index;
    int row;
    unsigned int column;
    unsigned int width = decoder->output_width;
    unsigned char *range_limit = decoder->sample_range_limit;

    for (row = 0; row < row_count; row++) {
        grim_jpeg_zero_far(output_buffer[row], width * sizeof(unsigned char));
        for (component_index = 0;
             component_index < component_count;
             component_index++) {
            input_pointer = input_buffer[row] + component_index;
            output_pointer = output_buffer[row];
            if (quantizer->on_odd_row) {
                input_pointer += (width - 1) * component_count;
                output_pointer += width - 1;
                direction = -1;
                component_direction = -component_count;
                error_pointer =
                    quantizer->fs_errors[component_index] + (width + 1);
            } else {
                direction = 1;
                component_direction = component_count;
                error_pointer = quantizer->fs_errors[component_index];
            }
            component_color_index = quantizer->color_index[component_index];
            component_colormap = quantizer->saved_colormap[component_index];
            current_error = 0;
            below_error = below_previous_error = 0;

            for (column = width; column > 0; column--) {
                current_error =
                    (current_error + error_pointer[direction] + 8) >> 4;
                current_error += *input_pointer;
                current_error = range_limit[current_error];
                pixel_code = component_color_index[current_error];
                *output_pointer += (unsigned char) pixel_code;
                current_error -= component_colormap[pixel_code];
                below_next_error = current_error;
                delta = current_error * 2;
                current_error += delta;
                error_pointer[0] =
                    (short) (below_previous_error + current_error);
                current_error += delta;
                below_previous_error = below_error + current_error;
                below_error = below_next_error;
                current_error += delta;
                input_pointer += component_direction;
                output_pointer += direction;
                error_pointer += direction;
            }
            error_pointer[0] = (short) below_previous_error;
        }
        quantizer->on_odd_row = quantizer->on_odd_row ? 0 : 1;
    }
}

static const unsigned char grim_jpeg_base_dither_matrix[16][16] = {
    {0, 192, 48, 240, 12, 204, 60, 252, 3, 195, 51, 243, 15, 207, 63, 255},
    {128, 64, 176, 112, 140, 76, 188, 124, 131, 67, 179, 115, 143, 79, 191, 127},
    {32, 224, 16, 208, 44, 236, 28, 220, 35, 227, 19, 211, 47, 239, 31, 223},
    {160, 96, 144, 80, 172, 108, 156, 92, 163, 99, 147, 83, 175, 111, 159, 95},
    {8, 200, 56, 248, 4, 196, 52, 244, 11, 203, 59, 251, 7, 199, 55, 247},
    {136, 72, 184, 120, 132, 68, 180, 116, 139, 75, 187, 123, 135, 71, 183, 119},
    {40, 232, 24, 216, 36, 228, 20, 212, 43, 235, 27, 219, 39, 231, 23, 215},
    {168, 104, 152, 88, 164, 100, 148, 84, 171, 107, 155, 91, 167, 103, 151, 87},
    {2, 194, 50, 242, 14, 206, 62, 254, 1, 193, 49, 241, 13, 205, 61, 253},
    {130, 66, 178, 114, 142, 78, 190, 126, 129, 65, 177, 113, 141, 77, 189, 125},
    {34, 226, 18, 210, 46, 238, 30, 222, 33, 225, 17, 209, 45, 237, 29, 221},
    {162, 98, 146, 82, 174, 110, 158, 94, 161, 97, 145, 81, 173, 109, 157, 93},
    {10, 202, 58, 250, 6, 198, 54, 246, 9, 201, 57, 249, 5, 197, 53, 245},
    {138, 74, 186, 122, 134, 70, 182, 118, 137, 73, 185, 121, 133, 69, 181, 117},
    {42, 234, 26, 218, 38, 230, 22, 214, 41, 233, 25, 217, 37, 229, 21, 213},
    {170, 106, 154, 90, 166, 102, 150, 86, 169, 105, 153, 89, 165, 101, 149, 85},
};

static int grim_jpeg_select_component_color_counts(
    grim_jpeg_decompress_quant1_source_t *decoder,
    int component_color_counts[])
{
    int component_count = decoder->output_color_components;
    int max_colors = decoder->desired_number_of_colors;
    int total_colors, integer_root, component_index, selected_component;
    unsigned char changed;
    long candidate_total;
    static const int rgb_order[3] = {1, 0, 2};

    integer_root = 1;
    do {
        integer_root++;
        candidate_total = integer_root;
        for (component_index = 1;
             component_index < component_count;
             component_index++)
            candidate_total *= integer_root;
    } while (candidate_total <= (long) max_colors);
    integer_root--;

    if (integer_root < 2) {
        decoder->error->message_code = 55;
        decoder->error->message_parameters[0] = (int) candidate_total;
        decoder->error->error_exit(
            (grim_jpeg_common_quant1_source_t *) decoder);
    }

    total_colors = 1;
    for (component_index = 0;
         component_index < component_count;
         component_index++) {
        component_color_counts[component_index] = integer_root;
        total_colors *= integer_root;
    }

    do {
        changed = 0;
        for (component_index = 0;
             component_index < component_count;
             component_index++) {
            selected_component =
                decoder->output_color_space == 2
                    ? rgb_order[component_index]
                    : component_index;
            candidate_total =
                total_colors / component_color_counts[selected_component];
            candidate_total *=
                component_color_counts[selected_component] + 1;
            if (candidate_total > (long) max_colors)
                break;
            component_color_counts[selected_component]++;
            total_colors = (int) candidate_total;
            changed = 1;
        }
    } while (changed);

    return total_colors;
}

static int grim_jpeg_quant1_output_value(
    grim_jpeg_decompress_quant1_source_t *decoder,
    int component_index,
    int value_index,
    int maximum_index)
{
    return (value_index * 255 + maximum_index / 2) / maximum_index;
}

static int grim_jpeg_quant1_largest_input_value(
    grim_jpeg_decompress_quant1_source_t *decoder,
    int component_index,
    int value_index,
    int maximum_index)
{
    return ((2 * value_index + 1) * 255 + maximum_index) /
        (2 * maximum_index);
}

static void grim_jpeg_create_colormap(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned char **colormap;
    int total_colors;
    int component_index, value_index, fill_index;
    int component_color_count, block_size, block_distance, pointer, value;

    total_colors = grim_jpeg_select_component_color_counts(
        decoder,
        quantizer->component_color_counts);

    if (decoder->output_color_components == 3) {
        int *message_parameters = decoder->error->message_parameters;
        message_parameters[0] = total_colors;
        message_parameters[1] = quantizer->component_color_counts[0];
        message_parameters[2] = quantizer->component_color_counts[1];
        message_parameters[3] = quantizer->component_color_counts[2];
        decoder->error->message_code = 93;
        decoder->error->emit_message(
            (grim_jpeg_common_quant1_source_t *) decoder,
            1);
    } else {
        decoder->error->message_code = 94;
        decoder->error->message_parameters[0] = total_colors;
        decoder->error->emit_message(
            (grim_jpeg_common_quant1_source_t *) decoder,
            1);
    }

    colormap = decoder->memory->alloc_sarray(
        (grim_jpeg_common_quant1_source_t *) decoder,
        1,
        (unsigned int) total_colors,
        (unsigned int) decoder->output_color_components);

    block_distance = total_colors;
    for (component_index = 0;
         component_index < decoder->output_color_components;
         component_index++) {
        component_color_count =
            quantizer->component_color_counts[component_index];
        block_size = block_distance / component_color_count;
        for (value_index = 0;
             value_index < component_color_count;
             value_index++) {
            value = grim_jpeg_quant1_output_value(
                decoder,
                component_index,
                value_index,
                component_color_count - 1);
            for (pointer = value_index * block_size;
                 pointer < total_colors;
                 pointer += block_distance) {
                for (fill_index = 0;
                     fill_index < block_size;
                     fill_index++)
                    colormap[component_index][pointer + fill_index] =
                        (unsigned char) value;
            }
        }
        block_distance = block_size;
    }

    quantizer->saved_colormap = colormap;
    quantizer->saved_actual_color_count = total_colors;
}

static void grim_jpeg_create_color_index(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned char *index_pointer;
    int component_index, input_value, largest_value;
    int component_color_count, block_size, output_index, padding;

    if (decoder->dither_mode == 1) {
        padding = 510;
        quantizer->is_padded = 1;
    } else {
        padding = 0;
        quantizer->is_padded = 0;
    }

    quantizer->color_index = decoder->memory->alloc_sarray(
        (grim_jpeg_common_quant1_source_t *) decoder,
        1,
        (unsigned int) (256 + padding),
        (unsigned int) decoder->output_color_components);

    block_size = quantizer->saved_actual_color_count;
    for (component_index = 0;
         component_index < decoder->output_color_components;
         component_index++) {
        component_color_count =
            quantizer->component_color_counts[component_index];
        block_size = block_size / component_color_count;
        if (padding)
            quantizer->color_index[component_index] += 255;

        index_pointer = quantizer->color_index[component_index];
        output_index = 0;
        largest_value = grim_jpeg_quant1_largest_input_value(
            decoder,
            component_index,
            0,
            component_color_count - 1);
        for (input_value = 0; input_value <= 255; input_value++) {
            while (input_value > largest_value) {
                output_index++;
                largest_value = grim_jpeg_quant1_largest_input_value(
                    decoder,
                    component_index,
                    output_index,
                    component_color_count - 1);
            }
            index_pointer[input_value] =
                (unsigned char) (output_index * block_size);
        }
        if (padding) {
            for (input_value = 1; input_value <= 255; input_value++) {
                index_pointer[-input_value] = index_pointer[0];
                index_pointer[255 + input_value] = index_pointer[255];
            }
        }
    }
}

static int (*grim_jpeg_make_ordered_dither_array(
    grim_jpeg_decompress_quant1_source_t *decoder,
    int color_count))[16]
{
    int (*ordered_dither)[16];
    int row, column;
    long numerator, denominator;

    ordered_dither = (int (*)[16]) decoder->memory->alloc_small(
        (grim_jpeg_common_quant1_source_t *) decoder,
        1,
        16 * 16 * sizeof(int));
    denominator = 2 * 256 * (long) (color_count - 1);
    for (row = 0; row < 16; row++) {
        for (column = 0; column < 16; column++) {
            numerator =
                (long) (255 - 2 * (int) grim_jpeg_base_dither_matrix[row][column]) *
                255;
            ordered_dither[row][column] =
                (int) (numerator < 0
                    ? -((-numerator) / denominator)
                    : numerator / denominator);
        }
    }
    return ordered_dither;
}

static void grim_jpeg_create_ordered_dither_tables(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    int (*ordered_dither)[16];
    int component_index, prior_component, component_color_count;

    for (component_index = 0;
         component_index < decoder->output_color_components;
         component_index++) {
        component_color_count =
            quantizer->component_color_counts[component_index];
        ordered_dither = 0;
        for (prior_component = 0;
             prior_component < component_index;
             prior_component++) {
            if (component_color_count ==
                quantizer->component_color_counts[prior_component]) {
                ordered_dither = quantizer->ordered_dither[prior_component];
                break;
            }
        }
        if (ordered_dither == 0)
            ordered_dither = grim_jpeg_make_ordered_dither_array(
                decoder,
                component_color_count);
        quantizer->ordered_dither[component_index] = ordered_dither;
    }
}

static void grim_jpeg_alloc_fs_workspace_quant1(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned int array_size;
    int component_index;

    array_size = (decoder->output_width + 2) * sizeof(short);
    for (component_index = 0;
         component_index < decoder->output_color_components;
         component_index++) {
        quantizer->fs_errors[component_index] = (short *)
            decoder->memory->alloc_large(
                (grim_jpeg_common_quant1_source_t *) decoder,
                1,
                array_size);
    }
}

static void grim_jpeg_start_pass_one_quantizer(
    grim_jpeg_decompress_quant1_source_t *decoder,
    unsigned char is_pre_scan)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned int array_size;
    int component_index;

    decoder->colormap = quantizer->saved_colormap;
    decoder->actual_number_of_colors = quantizer->saved_actual_color_count;

    switch (decoder->dither_mode) {
    case 0:
        if (decoder->output_color_components == 3)
            quantizer->color_quantize = grim_jpeg_color_quantize3;
        else
            quantizer->color_quantize = grim_jpeg_color_quantize;
        break;
    case 1:
        if (decoder->output_color_components == 3)
            quantizer->color_quantize = grim_jpeg_quantize3_ordered_dither;
        else
            quantizer->color_quantize = grim_jpeg_quantize_ordered_dither;
        quantizer->row_index = 0;
        if (!quantizer->is_padded)
            grim_jpeg_create_color_index(decoder);
        if (quantizer->ordered_dither[0] == 0)
            grim_jpeg_create_ordered_dither_tables(decoder);
        break;
    case 2:
        quantizer->color_quantize = grim_jpeg_quantize_fs_dither;
        quantizer->on_odd_row = 0;
        if (quantizer->fs_errors[0] == 0)
            grim_jpeg_alloc_fs_workspace_quant1(decoder);
        array_size = (decoder->output_width + 2) * sizeof(short);
        for (component_index = 0;
             component_index < decoder->output_color_components;
             component_index++)
            grim_jpeg_zero_far(
                quantizer->fs_errors[component_index],
                array_size);
        break;
    default:
        decoder->error->message_code = 47;
        decoder->error->error_exit(
            (grim_jpeg_common_quant1_source_t *) decoder);
        break;
    }
}

static void grim_jpeg_finish_pass_one_quantizer(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
}

static void grim_jpeg_new_color_map_one_quantizer(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    decoder->error->message_code = 45;
    decoder->error->error_exit(
        (grim_jpeg_common_quant1_source_t *) decoder);
}

void grim_jpeg_init_one_pass_quantizer(
    grim_jpeg_decompress_quant1_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer;

    quantizer = (grim_jpeg_color_quantizer_source_t *)
        decoder->memory->alloc_small(
            (grim_jpeg_common_quant1_source_t *) decoder,
            1,
            sizeof(grim_jpeg_color_quantizer_source_t));
    decoder->color_quantizer = quantizer;
    quantizer->start_pass = grim_jpeg_start_pass_one_quantizer;
    quantizer->finish_pass = grim_jpeg_finish_pass_one_quantizer;
    quantizer->new_color_map = grim_jpeg_new_color_map_one_quantizer;
    quantizer->fs_errors[0] = 0;
    quantizer->ordered_dither[0] = 0;

    if (decoder->output_color_components > 4) {
        decoder->error->message_code = 54;
        decoder->error->message_parameters[0] = 4;
        decoder->error->error_exit(
            (grim_jpeg_common_quant1_source_t *) decoder);
    }
    if (decoder->desired_number_of_colors > 256) {
        decoder->error->message_code = 56;
        decoder->error->message_parameters[0] = 256;
        decoder->error->error_exit(
            (grim_jpeg_common_quant1_source_t *) decoder);
    }

    grim_jpeg_create_colormap(decoder);
    grim_jpeg_create_color_index(decoder);
    if (decoder->dither_mode == 2)
        grim_jpeg_alloc_fs_workspace_quant1(decoder);
}
