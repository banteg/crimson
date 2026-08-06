struct grim_jpeg_source_manager_t {
    unsigned char *next_input_byte;
    unsigned int bytes_in_buffer;
    void *init_source;
    void *fill_input_buffer;
    void *skip_input_data;
    void *resync_to_restart;
    void *term_source;
    unsigned char *input_buffer;
    unsigned int input_size;
};

struct grim_jpeg_decompress_t {
    unsigned char fields[0x14];
    grim_jpeg_source_manager_t *source;
};

extern "C" void grim_jpeg_destroy(void *decoder);

extern "C" void grim_jpeg_source_noop(grim_jpeg_decompress_t *)
{
}

extern "C" bool grim_jpeg_fill_input_buffer(grim_jpeg_decompress_t *decoder)
{
    grim_jpeg_source_manager_t *source = decoder->source;
    source->next_input_byte = source->input_buffer;
    source->bytes_in_buffer = source->input_size;
    return true;
}

extern "C" void grim_jpeg_skip_input_data(
    grim_jpeg_decompress_t *decoder, unsigned int byte_count)
{
    grim_jpeg_source_manager_t *source = decoder->source;
    source->next_input_byte += byte_count;
    source->bytes_in_buffer -= byte_count;
}

extern "C" void grim_jpeg_destroy_decompress(void *decoder)
{
    grim_jpeg_destroy(decoder);
}
