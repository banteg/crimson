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
typedef void (__cdecl *grim_jpeg_free_pool_source_fn_t)(
    grim_jpeg_common_source_t *, int);

struct grim_jpeg_memory_source_t {
    grim_jpeg_alloc_small_source_fn_t alloc_small;
    void *fields_04[8];
    grim_jpeg_free_pool_source_fn_t free_pool;
    void *self_destruct;
    long max_memory_to_use;
};

typedef void (__cdecl *grim_jpeg_error_exit_source_fn_t)(
    grim_jpeg_common_source_t *);
typedef void (__cdecl *grim_jpeg_error_reset_source_fn_t)(
    grim_jpeg_common_source_t *);

struct grim_jpeg_error_source_t {
    grim_jpeg_error_exit_source_fn_t error_exit;
    void *emit_message;
    void *output_message;
    void *format_message;
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
};

struct grim_jpeg_decompress_source_t {
    grim_jpeg_error_source_t *error;
    grim_jpeg_memory_source_t *memory;
    void *progress;
    unsigned char is_decompressor;
    unsigned char fields_0d[3];
    int global_state;
    unsigned char fields_14[0x36];
    unsigned char quantize_colors;
    unsigned char fields_4b[0x31];
    int input_scan_number;
    unsigned char fields_80[0x0c];
    void *coefficient_bits;
    unsigned char fields_90[0x34];
    void *component_info;
    unsigned char fields_c8[0xb0];
    int unread_marker;
    grim_jpeg_decomp_master_source_t *master;
    unsigned char fields_180[0x0c];
    grim_jpeg_input_controller_source_t *input_controller;
    grim_jpeg_marker_reader_source_t *marker_reader;
    unsigned char fields_194[0x10];
    grim_jpeg_color_quantizer_source_t *color_quantizer;
};

extern "C" int grim_jpeg_consume_markers_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void grim_jpeg_start_input_pass_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void grim_jpeg_finish_input_pass_source(
    grim_jpeg_decompress_source_t *decoder);
extern "C" void grim_jpeg_free_pool_source(
    grim_jpeg_common_source_t *decoder, int pool);
extern "C" void grim_jpeg_free_small_source(
    grim_jpeg_common_source_t *decoder, void *allocation, unsigned int size);
extern "C" void grim_jpeg_mem_term_source(
    grim_jpeg_common_source_t *decoder);
extern "C" void *memcpy(void *destination, const void *source, unsigned int size);
extern "C" void *memset(void *destination, int value, unsigned int size);

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
