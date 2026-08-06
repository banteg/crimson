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
    unsigned char fields_10[0x0d];
    unsigned char channels;
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

extern "C" int grim_jpeg_consume_markers(
    grim_jpeg_decompress_leaf_t *decoder);

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
