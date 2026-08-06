struct grim_png_leaf_t {
    unsigned char fields_000[0x60];
    unsigned int transformations;
    unsigned char fields_064[0xaf];
    unsigned char interlace_type;
    unsigned char fields_114[3];
    unsigned char bit_depth;
    unsigned char user_bit_depth;
};

struct grim_png_info_leaf_t {
    unsigned char fields_00[8];
    unsigned int valid;
    unsigned int rowbytes;
    void *palette;
    unsigned short palette_count;
    unsigned char fields_16[7];
    unsigned char channels;
    unsigned char fields_1e[0x0a];
    float gamma;
    unsigned char srgb_intent;
};

struct grim_jpeg_decompress_leaf_t;

typedef int (__cdecl *grim_jpeg_consume_input_fn_t)(
    grim_jpeg_decompress_leaf_t *decoder);

struct grim_jpeg_input_controller_leaf_t {
    grim_jpeg_consume_input_fn_t consume_input;
};

struct grim_jpeg_decompress_leaf_t {
    unsigned char fields_000[0x18c];
    grim_jpeg_input_controller_leaf_t *input_controller;
};

struct grim_jpeg_common_leaf_t;

typedef void *(__cdecl *grim_jpeg_alloc_small_fn_t)(
    grim_jpeg_common_leaf_t *decoder, int pool_id, unsigned int size);
typedef void (__cdecl *grim_jpeg_self_destruct_fn_t)(
    grim_jpeg_common_leaf_t *decoder);

struct grim_jpeg_memory_manager_leaf_t {
    grim_jpeg_alloc_small_fn_t alloc_small;
    unsigned char fields_04[0x24];
    grim_jpeg_self_destruct_fn_t self_destruct;
};

struct grim_jpeg_common_leaf_t {
    unsigned char fields_00[4];
    grim_jpeg_memory_manager_leaf_t *memory;
    unsigned char fields_08[8];
    int global_state;
};

struct grim_jpeg_quant_table_leaf_t {
    unsigned char values[0x80];
    unsigned char sent_table;
};

struct grim_jpeg_huffman_table_leaf_t {
    unsigned char fields_000[0x111];
    unsigned char sent_table;
};

extern "C" int grim_jpeg_consume_markers(
    grim_jpeg_decompress_leaf_t *decoder);
extern "C" void __cdecl free(void *allocation);

extern "C" unsigned long grim_png_get_valid(
    grim_png_leaf_t *png,
    grim_png_info_leaf_t *info,
    unsigned long mask)
{
    if (png != 0 && info != 0) {
        return info->valid & mask;
    }
    return 0;
}

extern "C" unsigned long grim_png_get_rowbytes(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info)
{
    if (png != 0 && info != 0) {
        return info->rowbytes;
    }
    return 0;
}

extern "C" unsigned char grim_png_get_channels(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info)
{
    if (png != 0 && info != 0) {
        return info->channels;
    }
    return 0;
}

extern "C" unsigned long grim_png_get_gamma(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info, double *gamma)
{
    if (png != 0 && info != 0 && (info->valid & 1) != 0 && gamma != 0) {
        *gamma = info->gamma;
        return 1;
    }
    return 0;
}

extern "C" unsigned long grim_png_get_srgb(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info, int *intent)
{
    if (png != 0 && info != 0 && (info->valid & 0x800) != 0 && intent != 0) {
        *intent = info->srgb_intent;
        return 0x800;
    }
    return 0;
}

extern "C" unsigned long grim_png_get_palette(
    grim_png_leaf_t *png,
    grim_png_info_leaf_t *info,
    void **palette,
    int *palette_count)
{
    if (png != 0 && info != 0 && (info->valid & 8) != 0 && palette != 0) {
        *palette = info->palette;
        *palette_count = info->palette_count;
        return 8;
    }
    return 0;
}

extern "C" void grim_png_set_bgr(grim_png_leaf_t *png)
{
    png->transformations |= 1;
}

extern "C" void grim_png_set_swap(grim_png_leaf_t *png)
{
    if (png->bit_depth == 16) {
        png->transformations |= 0x10;
    }
}

extern "C" void grim_png_set_packing(grim_png_leaf_t *png)
{
    if (png->bit_depth < 8) {
        png->transformations |= 4;
        png->user_bit_depth = 8;
    }
}

extern "C" int grim_png_set_interlace_handling(grim_png_leaf_t *png)
{
    if (png->interlace_type != 0) {
        png->transformations |= 2;
        return 7;
    }
    return 1;
}

extern "C" void grim_png_set_gamma(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info, double gamma)
{
    if (png != 0 && info != 0) {
        info->valid |= 1;
        info->gamma = static_cast<float>(gamma);
    }
}

extern "C" void grim_png_set_srgb(
    grim_png_leaf_t *png, grim_png_info_leaf_t *info, int intent)
{
    if (png != 0 && info != 0) {
        info->valid |= 0x800;
        info->srgb_intent = static_cast<unsigned char>(intent);
    }
}

extern "C" void grim_png_set_palette(
    grim_png_leaf_t *png,
    grim_png_info_leaf_t *info,
    void *palette,
    int palette_count)
{
    if (png != 0 && info != 0) {
        info->valid |= 8;
        info->palette = palette;
        info->palette_count = static_cast<unsigned short>(palette_count);
    }
}

extern "C" void grim_png_free(grim_png_leaf_t *png, void *allocation)
{
    if (png != 0 && allocation != 0) {
        free(allocation);
    }
}

extern "C" long grim_jpeg_div_round_up(long value, long divisor)
{
    return (value + divisor - 1) / divisor;
}

extern "C" long grim_jpeg_round_up(long value, long divisor)
{
    long sum = value + divisor - 1;
    return sum - sum % divisor;
}

extern "C" void grim_jpeg_finish_input_pass(
    grim_jpeg_decompress_leaf_t *decoder)
{
    decoder->input_controller->consume_input = grim_jpeg_consume_markers;
}

extern "C" void grim_jpeg_destroy(grim_jpeg_common_leaf_t *decoder)
{
    if (decoder->memory != 0) {
        decoder->memory->self_destruct(decoder);
    }
    decoder->memory = 0;
    decoder->global_state = 0;
}

extern "C" grim_jpeg_quant_table_leaf_t *grim_jpeg_alloc_quant_table(
    grim_jpeg_common_leaf_t *decoder)
{
    grim_jpeg_quant_table_leaf_t *table =
        static_cast<grim_jpeg_quant_table_leaf_t *>(
            decoder->memory->alloc_small(decoder, 0, 0x82));
    table->sent_table = 0;
    return table;
}

extern "C" grim_jpeg_huffman_table_leaf_t *grim_jpeg_alloc_huffman_table(
    grim_jpeg_common_leaf_t *decoder)
{
    grim_jpeg_huffman_table_leaf_t *table =
        static_cast<grim_jpeg_huffman_table_leaf_t *>(
            decoder->memory->alloc_small(decoder, 0, 0x112));
    table->sent_table = 0;
    return table;
}
