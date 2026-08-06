/*
 * Matcher-only adaptations of IJG libjpeg 6a routines.
 * Copyright (C) 1991-1996, Thomas G. Lane.
 *
 * Function names are changed to keep scratch objects isolated. The original
 * distribution terms are preserved in third_party/headers/jpeglib.h.
 */

struct grim_jpeg_common_source_t;
struct grim_jpeg_decompress_source_t;

typedef void *(__cdecl *grim_jpeg_alloc_small_source_fn_t)(
    grim_jpeg_common_source_t *, int, unsigned int);
typedef void *(__cdecl *grim_jpeg_alloc_large_source_fn_t)(
    grim_jpeg_common_source_t *, int, unsigned int);
typedef void (__cdecl *grim_jpeg_free_pool_source_fn_t)(
    grim_jpeg_common_source_t *, int);

struct grim_jpeg_memory_source_t {
    grim_jpeg_alloc_small_source_fn_t alloc_small;
    grim_jpeg_alloc_large_source_fn_t alloc_large;
    void *fields_08[7];
    grim_jpeg_free_pool_source_fn_t free_pool;
    void *self_destruct;
    long max_memory_to_use;
};

typedef void (__cdecl *grim_jpeg_error_exit_source_fn_t)(
    grim_jpeg_common_source_t *);
typedef void (__cdecl *grim_jpeg_emit_message_source_fn_t)(
    grim_jpeg_common_source_t *, int);
typedef void (__cdecl *grim_jpeg_output_message_source_fn_t)(
    grim_jpeg_common_source_t *);
typedef void (__cdecl *grim_jpeg_format_message_source_fn_t)(
    grim_jpeg_common_source_t *, char *);
typedef void (__cdecl *grim_jpeg_error_reset_source_fn_t)(
    grim_jpeg_common_source_t *);

struct grim_jpeg_error_source_t {
    grim_jpeg_error_exit_source_fn_t error_exit;
    grim_jpeg_emit_message_source_fn_t emit_message;
    grim_jpeg_output_message_source_fn_t output_message;
    grim_jpeg_format_message_source_fn_t format_message;
    grim_jpeg_error_reset_source_fn_t reset_error_manager;
    int message_code;
    int message_parameters[20];
    int trace_level;
    long warning_count;
    const char *const *message_table;
    int last_message;
    const char *const *addon_message_table;
    int first_addon_message;
    int last_addon_message;
};

struct grim_jpeg_common_source_t {
    grim_jpeg_error_source_t *error;
    grim_jpeg_memory_source_t *memory;
    void *progress;
    unsigned char is_decompressor;
    unsigned char fields_0d[3];
    int global_state;
};

typedef int (__cdecl *grim_jpeg_consume_input_source_fn_t)(
    grim_jpeg_decompress_source_t *);
typedef void (__cdecl *grim_jpeg_input_method_source_fn_t)(
    grim_jpeg_decompress_source_t *);

struct grim_jpeg_input_controller_source_t {
    grim_jpeg_consume_input_source_fn_t consume_input;
    grim_jpeg_input_method_source_fn_t reset_input_controller;
    grim_jpeg_input_method_source_fn_t start_input_pass;
    grim_jpeg_input_method_source_fn_t finish_input_pass;
    unsigned char has_multiple_scans;
    unsigned char eoi_reached;
    unsigned char fields_12[2];
    unsigned char inheaders;
    unsigned char fields_15[3];
};

struct grim_jpeg_marker_reader_source_t {
    grim_jpeg_input_method_source_fn_t reset_marker_reader;
    void *methods[19];
    unsigned char saw_soi;
    unsigned char saw_sof;
    unsigned char fields_52[2];
    int next_restart_number;
    unsigned int discarded_bytes;
};

struct grim_jpeg_decomp_master_source_t {
    void *prepare_for_output_pass;
    void *finish_output_pass;
    unsigned char is_dummy_pass;
    unsigned char fields_09[3];
    int pass_number;
};

typedef void (__cdecl *grim_jpeg_finish_quantize_source_fn_t)(
    grim_jpeg_decompress_source_t *);

struct grim_jpeg_color_quantizer_source_t {
    void *start_pass;
    void *color_quantize;
    grim_jpeg_finish_quantize_source_fn_t finish_pass;
    void *new_color_map;
    unsigned char **saved_colormap;
    int desired_color_count;
    unsigned char fields_18[0x04];
    unsigned char needs_zeroed;
    unsigned char fields_1d[3];
    unsigned char fields_20[0x24];
    short *fs_errors[4];
};

struct grim_jpeg_quantization_table_source_t {
    unsigned short quantization_values[64];
};

struct grim_jpeg_component_source_t {
    unsigned char fields_00[0x0c];
    int vertical_sampling_factor;
    unsigned char fields_10[0x38];
    int last_row_height;
    grim_jpeg_quantization_table_source_t *quantization_table;
    unsigned char fields_50[0x04];
};

typedef int (__cdecl *grim_jpeg_decompress_data_source_fn_t)(
    grim_jpeg_decompress_source_t *, unsigned char ***);

struct grim_jpeg_coefficient_controller_source_t {
    void *start_input_pass;
    void *consume_data;
    void *start_output_pass;
    grim_jpeg_decompress_data_source_fn_t decompress_data;
    void *coefficient_arrays;
    unsigned int MCU_counter;
    int MCU_vertical_offset;
    int MCU_rows_per_iMCU_row;
    unsigned char fields_20[0x50];
    int *coefficient_bits_latch;
};

typedef void (__cdecl *grim_jpeg_merged_upmethod_source_fn_t)(
    grim_jpeg_decompress_source_t *,
    unsigned char ***,
    unsigned int,
    unsigned char **);

struct grim_jpeg_separate_upsampler_source_t {
    void *start_pass;
    void *upsample;
    unsigned char need_context_rows;
    unsigned char fields_09[3];
    unsigned char **color_buffer[10];
    void *methods[10];
    int next_row_out;
    unsigned int rows_to_go;
};

struct grim_jpeg_merged_upsampler_source_t {
    void *start_pass;
    void *upsample;
    unsigned char need_context_rows;
    unsigned char fields_09[3];
    grim_jpeg_merged_upmethod_source_fn_t upmethod;
    int *cr_r_table;
    int *cb_b_table;
    int *cr_g_table;
    int *cb_g_table;
    unsigned char *spare_row;
    unsigned char spare_full;
    unsigned char fields_25[3];
    unsigned int out_row_width;
    unsigned int rows_to_go;
};

struct grim_jpeg_decompress_source_t {
    grim_jpeg_error_source_t *error;
    grim_jpeg_memory_source_t *memory;
    void *progress;
    unsigned char is_decompressor;
    unsigned char fields_0d[3];
    int global_state;
    unsigned char fields_14[0x0c];
    int component_count;
    unsigned char fields_24[0x25];
    unsigned char do_block_smoothing;
    unsigned char quantize_colors;
    unsigned char fields_4b[0x11];
    unsigned int output_width;
    unsigned int output_height;
    int output_color_components;
    unsigned char fields_68[0x08];
    int actual_number_of_colors;
    unsigned char **colormap;
    unsigned char fields_78[0x04];
    int input_scan_number;
    unsigned int input_iMCU_row;
    unsigned char fields_84[0x04];
    unsigned int output_iMCU_row;
    int (*coefficient_bits)[64];
    unsigned char fields_90[0x34];
    grim_jpeg_component_source_t *component_info;
    unsigned char progressive_mode;
    unsigned char fields_c9[0x47];
    int max_v_samp_factor;
    unsigned char fields_114[0x04];
    unsigned int total_iMCU_rows;
    unsigned char fields_11c[0x04];
    int components_in_scan;
    grim_jpeg_component_source_t *current_components[4];
    unsigned char fields_134[0x44];
    int unread_marker;
    grim_jpeg_decomp_master_source_t *master;
    void *main_controller;
    grim_jpeg_coefficient_controller_source_t *coefficient_controller;
    void *postprocessor;
    grim_jpeg_input_controller_source_t *input_controller;
    grim_jpeg_marker_reader_source_t *marker_reader;
    unsigned char fields_194[0x08];
    void *upsampler;
    void *color_converter;
    grim_jpeg_color_quantizer_source_t *color_quantizer;
};

extern "C" int grim_jpeg_consume_markers_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void grim_jpeg_start_input_pass_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void grim_jpeg_finish_input_pass_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void __fastcall grim_jpeg_start_iMCU_row_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" int grim_jpeg_decompress_data_source(
    grim_jpeg_decompress_source_t *decoder, unsigned char ***output_buffer);
extern "C" int grim_jpeg_decompress_smooth_data_source(
    grim_jpeg_decompress_source_t *decoder, unsigned char ***output_buffer);
extern "C" void grim_jpeg_free_pool_source(
    grim_jpeg_common_source_t *decoder, int pool);
extern "C" void grim_jpeg_free_small_source(
    grim_jpeg_common_source_t *decoder, void *allocation, unsigned int size);
extern "C" void grim_jpeg_mem_term_source(
    grim_jpeg_common_source_t *decoder);
extern "C" void grim_jpeg_destroy_source(
    grim_jpeg_common_source_t *decoder);
extern "C" void grim_jpeg_reset_error_manager_source(
    grim_jpeg_common_source_t *decoder);
extern "C" const char *const grim_jpeg_std_message_table_source[];
extern "C" __declspec(noreturn) void exit(int status);
extern "C" int sprintf(char *buffer, const char *format, ...);
extern "C" void *memcpy(void *destination, const void *source, unsigned int size);
extern "C" void *memset(void *destination, int value, unsigned int size);

extern "C" void grim_jpeg_error_exit(grim_jpeg_common_source_t *decoder)
{
    decoder->error->output_message(decoder);
    grim_jpeg_destroy_source(decoder);
    exit(1);
}

extern "C" void grim_jpeg_output_message(grim_jpeg_common_source_t *decoder)
{
    char buffer[200];

    decoder->error->format_message(decoder, buffer);
}

extern "C" void grim_jpeg_emit_message(
    grim_jpeg_common_source_t *decoder, int message_level)
{
    grim_jpeg_error_source_t *error = decoder->error;

    if (message_level < 0) {
        if (error->warning_count == 0 || error->trace_level >= 3)
            error->output_message(decoder);
        error->warning_count++;
    } else if (error->trace_level >= message_level) {
        error->output_message(decoder);
    }
}

extern "C" void grim_jpeg_format_message(
    grim_jpeg_common_source_t *decoder, char *buffer)
{
    grim_jpeg_error_source_t *error = decoder->error;
    int message_code = error->message_code;
    const char *message_text = 0;
    const char *message_pointer;
    char character;
    bool is_string;

    if (message_code > 0 && message_code <= error->last_message) {
        message_text = error->message_table[message_code];
    } else if (error->addon_message_table != 0 &&
               message_code >= error->first_addon_message &&
               message_code <= error->last_addon_message) {
        message_text = error->addon_message_table[
            message_code - error->first_addon_message];
    }

    if (message_text == 0) {
        error->message_parameters[0] = message_code;
        message_text = error->message_table[0];
    }

    is_string = false;
    message_pointer = message_text;
    while ((character = *message_pointer++) != '\0') {
        if (character == '%') {
            if (*message_pointer == 's')
                is_string = true;
            break;
        }
    }

    if (is_string) {
        sprintf(
            buffer,
            message_text,
            reinterpret_cast<char *>(error->message_parameters));
    } else {
        sprintf(
            buffer,
            message_text,
            error->message_parameters[0],
            error->message_parameters[1],
            error->message_parameters[2],
            error->message_parameters[3],
            error->message_parameters[4],
            error->message_parameters[5],
            error->message_parameters[6],
            error->message_parameters[7]);
    }
}

extern "C" grim_jpeg_error_source_t *grim_jpeg_std_error(
    grim_jpeg_error_source_t *error)
{
    error->error_exit = grim_jpeg_error_exit;
    error->emit_message = grim_jpeg_emit_message;
    error->output_message = grim_jpeg_output_message;
    error->format_message = grim_jpeg_format_message;
    error->reset_error_manager = grim_jpeg_reset_error_manager_source;

    error->trace_level = 0;
    error->warning_count = 0;
    error->message_code = 0;

    error->message_table = grim_jpeg_std_message_table_source;
    error->last_message = 119;
    error->addon_message_table = 0;
    error->first_addon_message = 0;
    error->last_addon_message = 0;

    return error;
}

extern "C" void grim_jpeg_reset_marker_reader(
    grim_jpeg_decompress_source_t *decoder)
{
    decoder->component_info = 0;
    decoder->input_scan_number = 0;
    decoder->unread_marker = 0;
    decoder->marker_reader->saw_soi = 0;
    decoder->marker_reader->saw_sof = 0;
    decoder->marker_reader->discarded_bytes = 0;
}

extern "C" void grim_jpeg_copy_sample_rows(
    unsigned char **input_array,
    int source_row,
    unsigned char **output_array,
    int destination_row,
    int row_count,
    unsigned int column_count)
{
    unsigned char *input;
    unsigned char *output;
    unsigned int count = column_count;
    int row;

    input_array += source_row;
    output_array += destination_row;

    for (row = row_count; row > 0; row--) {
        input = *input_array++;
        output = *output_array++;
        memcpy(output, input, count);
    }
}

extern "C" void grim_jpeg_copy_block_row(
    short (*input_row)[64],
    short (*output_row)[64],
    unsigned int block_count)
{
    memcpy(output_row, input_row, block_count * 128);
}

extern "C" void grim_jpeg_zero_far(void *target, unsigned int size)
{
    memset(target, 0, size);
}

extern "C" void grim_jpeg_reset_input_controller(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_input_controller_source_t *input = decoder->input_controller;

    input->has_multiple_scans &= 0;
    input->eoi_reached &= 0;
    input->consume_input = grim_jpeg_consume_markers_source;
    input->inheaders = 1;
    decoder->error->reset_error_manager(
        reinterpret_cast<grim_jpeg_common_source_t *>(decoder));
    decoder->marker_reader->reset_marker_reader(decoder);
    decoder->coefficient_bits = 0;
}

extern "C" void grim_jpeg_init_input_controller(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_input_controller_source_t *input =
        static_cast<grim_jpeg_input_controller_source_t *>(
            decoder->memory->alloc_small(
                reinterpret_cast<grim_jpeg_common_source_t *>(decoder),
                0,
                sizeof(grim_jpeg_input_controller_source_t)));

    decoder->input_controller = input;
    input->has_multiple_scans &= 0;
    input->eoi_reached &= 0;
    input->consume_input = grim_jpeg_consume_markers_source;
    input->reset_input_controller = grim_jpeg_reset_input_controller;
    input->start_input_pass = grim_jpeg_start_input_pass_source;
    input->finish_input_pass = grim_jpeg_finish_input_pass_source;
    input->inheaders = 1;
}

extern "C" {
static void grim_jpeg_out_of_memory(
    grim_jpeg_common_source_t *decoder, int code)
{
    decoder->error->message_code = 53;
    decoder->error->message_parameters[0] = code;
    decoder->error->error_exit(decoder);
}
}

/*
 * Keep the internal helper live through an ordinary translation-unit call.
 * The archived object has several such callers and uses an EAX/EDX local
 * calling convention for this non-exported routine.
 */
extern "C" void grim_jpeg_out_of_memory_callsite(
    grim_jpeg_common_source_t *decoder, int code)
{
    grim_jpeg_out_of_memory(decoder, code);
}

extern "C" void grim_jpeg_self_destruct(
    grim_jpeg_common_source_t *decoder)
{
    int pool;

    for (pool = 1; pool >= 0; pool--)
        grim_jpeg_free_pool_source(decoder, pool);

    grim_jpeg_free_small_source(decoder, decoder->memory, 0x50);
    decoder->memory = 0;
    grim_jpeg_mem_term_source(decoder);
}

extern "C" void grim_jpeg_abort(grim_jpeg_common_source_t *decoder)
{
    int pool;

    for (pool = 1; pool > 0; pool--)
        decoder->memory->free_pool(decoder, pool);

    decoder->global_state = decoder->is_decompressor ? 200 : 100;
}

extern "C" void grim_jpeg_finish_output_pass(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_decomp_master_source_t *master = decoder->master;

    if (decoder->quantize_colors)
        decoder->color_quantizer->finish_pass(decoder);
    master->pass_number++;
}

extern "C" long grim_jpeg_mem_available(
    grim_jpeg_common_source_t *decoder,
    long minimum_bytes,
    long maximum_bytes,
    long already_allocated)
{
    return maximum_bytes;
}

extern "C" void grim_jpeg_open_backing_store(
    grim_jpeg_common_source_t *decoder,
    void *backing_store,
    long total_bytes)
{
    decoder->error->message_code = 48;
    decoder->error->error_exit(decoder);
}

extern "C" void grim_jpeg_start_pass_upsample(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_separate_upsampler_source_t *upsampler =
        static_cast<grim_jpeg_separate_upsampler_source_t *>(decoder->upsampler);

    upsampler->next_row_out = decoder->max_v_samp_factor;
    upsampler->rows_to_go = decoder->output_height;
}

extern "C" void __fastcall grim_jpeg_start_iMCU_row_source(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_coefficient_controller_source_t *coefficient_controller =
        decoder->coefficient_controller;

    if (decoder->components_in_scan > 1) {
        coefficient_controller->MCU_rows_per_iMCU_row = 1;
    } else {
        if (decoder->input_iMCU_row < decoder->total_iMCU_rows - 1)
            coefficient_controller->MCU_rows_per_iMCU_row =
                decoder->current_components[0]->vertical_sampling_factor;
        else
            coefficient_controller->MCU_rows_per_iMCU_row =
                decoder->current_components[0]->last_row_height;
    }

    coefficient_controller->MCU_counter = 0;
    coefficient_controller->MCU_vertical_offset = 0;
}

extern "C" {
static unsigned char grim_jpeg_smoothing_ok(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_coefficient_controller_source_t *coefficient_controller =
        decoder->coefficient_controller;
    unsigned char smoothing_useful = 0;
    int component_index;
    int coefficient_index;
    grim_jpeg_component_source_t *component;
    grim_jpeg_quantization_table_source_t *quantization_table;
    int *coefficient_bits;
    int *coefficient_bits_latch;

    if (!decoder->progressive_mode || decoder->coefficient_bits == 0)
        return 0;

    if (coefficient_controller->coefficient_bits_latch == 0)
        coefficient_controller->coefficient_bits_latch = static_cast<int *>(
            decoder->memory->alloc_small(
                reinterpret_cast<grim_jpeg_common_source_t *>(decoder),
                1,
                decoder->component_count * (6 * sizeof(int))));
    coefficient_bits_latch = coefficient_controller->coefficient_bits_latch;

    for (component_index = 0, component = decoder->component_info;
         component_index < decoder->component_count;
         component_index++, component++) {
        if ((quantization_table = component->quantization_table) == 0)
            return 0;
        if (quantization_table->quantization_values[0] == 0 ||
            quantization_table->quantization_values[1] == 0 ||
            quantization_table->quantization_values[8] == 0 ||
            quantization_table->quantization_values[16] == 0 ||
            quantization_table->quantization_values[9] == 0 ||
            quantization_table->quantization_values[2] == 0)
            return 0;
        coefficient_bits = decoder->coefficient_bits[component_index];
        if (coefficient_bits[0] < 0)
            return 0;
        for (coefficient_index = 1;
             coefficient_index <= 5;
             coefficient_index++) {
            coefficient_bits_latch[coefficient_index] =
                coefficient_bits[coefficient_index];
            if (coefficient_bits[coefficient_index] != 0)
                smoothing_useful = 1;
        }
        coefficient_bits_latch += 6;
    }

    return smoothing_useful;
}
}

extern "C" void grim_jpeg_start_coefficient_output_pass(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_coefficient_controller_source_t *coefficient_controller =
        decoder->coefficient_controller;

    if (coefficient_controller->coefficient_arrays != 0) {
        if (decoder->do_block_smoothing && grim_jpeg_smoothing_ok(decoder))
            coefficient_controller->decompress_data =
                grim_jpeg_decompress_smooth_data_source;
        else
            coefficient_controller->decompress_data =
                grim_jpeg_decompress_data_source;
    }
    decoder->output_iMCU_row = 0;
}

extern "C" void grim_jpeg_fullsize_upsample(
    grim_jpeg_decompress_source_t *decoder,
    void *component,
    unsigned char **input_data,
    unsigned char ***output_data)
{
    *output_data = input_data;
}

extern "C" void grim_jpeg_noop_upsample(
    grim_jpeg_decompress_source_t *decoder,
    void *component,
    unsigned char **input_data,
    unsigned char ***output_data)
{
    *output_data = 0;
}

extern "C" void grim_jpeg_h2v1_upsample(
    grim_jpeg_decompress_source_t *decoder,
    void *component,
    unsigned char **input_data,
    unsigned char ***output_data_pointer)
{
    unsigned char **output_data = *output_data_pointer;
    unsigned char *input_pointer;
    unsigned char *output_pointer;
    unsigned char input_value;
    unsigned char *output_end;
    int input_row;

    for (input_row = 0;
         input_row < decoder->max_v_samp_factor;
         input_row++) {
        input_pointer = input_data[input_row];
        output_pointer = output_data[input_row];
        output_end = output_pointer + decoder->output_width;
        while (output_pointer < output_end) {
            input_value = *input_pointer++;
            *output_pointer++ = input_value;
            *output_pointer++ = input_value;
        }
    }
}

extern "C" void grim_jpeg_h2v2_upsample(
    grim_jpeg_decompress_source_t *decoder,
    void *component,
    unsigned char **input_data,
    unsigned char ***output_data_pointer)
{
    unsigned char **output_data = *output_data_pointer;
    unsigned char *input_pointer;
    unsigned char *output_pointer;
    unsigned char input_value;
    unsigned char *output_end;
    int input_row;
    int output_row;

    input_row = output_row = 0;
    while (output_row < decoder->max_v_samp_factor) {
        input_pointer = input_data[input_row];
        output_pointer = output_data[output_row];
        output_end = output_pointer + decoder->output_width;
        while (output_pointer < output_end) {
            input_value = *input_pointer++;
            *output_pointer++ = input_value;
            *output_pointer++ = input_value;
        }
        grim_jpeg_copy_sample_rows(
            output_data,
            output_row,
            output_data,
            output_row + 1,
            1,
            decoder->output_width);
        input_row++;
        output_row += 2;
    }
}

extern "C" void grim_jpeg_grayscale_convert(
    grim_jpeg_decompress_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int input_row,
    unsigned char **output_buffer,
    int row_count)
{
    grim_jpeg_copy_sample_rows(
        input_buffer[0],
        static_cast<int>(input_row),
        output_buffer,
        0,
        row_count,
        decoder->output_width);
}

extern "C" void grim_jpeg_start_pass_merged_upsample(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_merged_upsampler_source_t *upsampler =
        static_cast<grim_jpeg_merged_upsampler_source_t *>(decoder->upsampler);

    upsampler->spare_full = 0;
    upsampler->rows_to_go = decoder->output_height;
}

extern "C" void grim_jpeg_new_color_map_2_quant(
    grim_jpeg_decompress_source_t *decoder)
{
    decoder->color_quantizer->needs_zeroed = 1;
}

extern "C" void grim_jpeg_new_color_map_1_quant(
    grim_jpeg_decompress_source_t *decoder)
{
    decoder->error->message_code = 45;
    decoder->error->error_exit(
        reinterpret_cast<grim_jpeg_common_source_t *>(decoder));
}

typedef void (__cdecl *grim_jpeg_post_process_source_fn_t)(
    grim_jpeg_decompress_source_t *,
    unsigned char ***,
    unsigned int *,
    unsigned int,
    unsigned char **,
    unsigned int *,
    unsigned int);

struct grim_jpeg_postprocessor_source_t {
    void *start_pass;
    grim_jpeg_post_process_source_fn_t post_process_data;
};

extern "C" void grim_jpeg_process_data_crank_post(
    grim_jpeg_decompress_source_t *decoder,
    unsigned char **output_buffer,
    unsigned int *output_row_counter,
    unsigned int output_rows_available)
{
    grim_jpeg_postprocessor_source_t *postprocessor =
        static_cast<grim_jpeg_postprocessor_source_t *>(decoder->postprocessor);

    postprocessor->post_process_data(
        decoder,
        0,
        0,
        0,
        output_buffer,
        output_row_counter,
        output_rows_available);
}

extern "C" void grim_jpeg_start_coefficient_input_pass(
    grim_jpeg_decompress_source_t *decoder)
{
    decoder->input_iMCU_row = 0;
    grim_jpeg_start_iMCU_row_source(decoder);
}

extern "C" void grim_jpeg_merged_1v_upsample(
    grim_jpeg_decompress_source_t *decoder,
    unsigned char ***input_buffer,
    unsigned int *input_row_group_counter,
    unsigned int input_row_groups_available,
    unsigned char **output_buffer,
    unsigned int *output_row_counter,
    unsigned int output_rows_available)
{
    grim_jpeg_merged_upsampler_source_t *upsampler =
        static_cast<grim_jpeg_merged_upsampler_source_t *>(decoder->upsampler);

    upsampler->upmethod(
        decoder,
        input_buffer,
        *input_row_group_counter,
        output_buffer + *output_row_counter);
    (*output_row_counter)++;
    (*input_row_group_counter)++;
}

extern "C" {
struct grim_jpeg_color_box_source_t {
    int c0_min;
    int c0_max;
    int c1_min;
    int c1_max;
    int c2_min;
    int c2_max;
    long volume;
    long color_count;
};

void grim_jpeg_update_color_box_source(
    grim_jpeg_decompress_source_t *decoder,
    grim_jpeg_color_box_source_t *box);
int grim_jpeg_median_cut_source(
    grim_jpeg_decompress_source_t *decoder,
    grim_jpeg_color_box_source_t *boxes,
    int box_count,
    int desired_color_count);
void grim_jpeg_compute_color_source(
    grim_jpeg_decompress_source_t *decoder,
    grim_jpeg_color_box_source_t *box,
    int color_index);

static void grim_jpeg_select_colors_callsite(
    grim_jpeg_decompress_source_t *decoder, int desired_color_count)
{
    grim_jpeg_color_box_source_t *boxes =
        static_cast<grim_jpeg_color_box_source_t *>(
            decoder->memory->alloc_small(
                reinterpret_cast<grim_jpeg_common_source_t *>(decoder),
                1,
                desired_color_count * sizeof(grim_jpeg_color_box_source_t)));
    int box_count;
    int index;

    box_count = 1;
    boxes[0].c0_min = 0;
    boxes[0].c0_max = 31;
    boxes[0].c1_min = 0;
    boxes[0].c1_max = 63;
    boxes[0].c2_min = 0;
    boxes[0].c2_max = 31;
    grim_jpeg_update_color_box_source(decoder, &boxes[0]);
    box_count = grim_jpeg_median_cut_source(
        decoder, boxes, box_count, desired_color_count);
    for (index = 0; index < box_count; index++)
        grim_jpeg_compute_color_source(decoder, &boxes[index], index);

    decoder->actual_number_of_colors = box_count;
    decoder->error->message_code = 95;
    decoder->error->message_parameters[0] = box_count;
    decoder->error->emit_message(
        reinterpret_cast<grim_jpeg_common_source_t *>(decoder), 1);
}

static void grim_jpeg_alloc_fs_workspace(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;
    unsigned int array_size;
    int component_index;

    array_size = (decoder->output_width + 2) * sizeof(short);
    for (component_index = 0;
         component_index < decoder->output_color_components;
         component_index++) {
        quantizer->fs_errors[component_index] = static_cast<short *>(
            decoder->memory->alloc_large(
                reinterpret_cast<grim_jpeg_common_source_t *>(decoder),
                1,
                array_size));
    }
}
}

extern "C" void grim_jpeg_alloc_fs_workspace_callsite(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_alloc_fs_workspace(decoder);
}

extern "C" void grim_jpeg_finish_quantizer_pass_one(
    grim_jpeg_decompress_source_t *decoder)
{
    grim_jpeg_color_quantizer_source_t *quantizer = decoder->color_quantizer;

    decoder->colormap = quantizer->saved_colormap;
    grim_jpeg_select_colors_callsite(decoder, quantizer->desired_color_count);
    quantizer->needs_zeroed = 1;
}
